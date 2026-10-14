import multiprocessing
import os
import signal
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.mac_cleanup.jsonio import atomic_write_json, read_json
from scripts.mac_cleanup.models import Batch, Issue, Manifest, Risk, Severity, Target
from scripts.mac_cleanup.sessions import InvalidTransition, Session


def _fork_inside_session_lock_and_exit(
    session_path: str, sender: object
) -> None:
    session = Session.load(session_path)
    with session.operation_lock():
        child_pid = os.fork()
        if child_pid == 0:
            try:
                resumed = Session.load(session_path)
                with resumed.operation_lock():
                    pass
                sender.send(("acquired", os.getpid()))  # type: ignore[attr-defined]
            except BaseException as error:
                sender.send(("error", repr(error)))  # type: ignore[attr-defined]
            finally:
                sender.close()  # type: ignore[attr-defined]
                os._exit(0)
        sender.send(("child", child_pid))  # type: ignore[attr-defined]
        os._exit(0)


class SessionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.session_path = Path(self.directory.name) / "session"
        self.target = Target(
            id="cache-a",
            path="/private/tmp/cache-a",
            kind="directory",
            risk=Risk.SAFE_REGENERABLE,
            fingerprint="fingerprint-a",
            logical_bytes=42,
        )
        self.manifest = Manifest(batches=(Batch(id="safe-caches", targets=(self.target,)),))

    def tearDown(self) -> None:
        self.directory.cleanup()

    def test_artifacts_are_created_only_as_data_becomes_available(self) -> None:
        session = Session.create(self.session_path)

        self.assertTrue((self.session_path / "state.json").is_file())
        self.assertFalse((self.session_path / "inventory.json").exists())
        self.assertFalse((self.session_path / "policy.json").exists())
        self.assertFalse((self.session_path / "manifest.json").exists())
        self.assertFalse((self.session_path / "report.md").exists())

        session.write_inventory({"schema_version": 1, "candidates": []})
        session.write_policy({"schema_version": 1, "allow_review_required": False})
        session.write_manifest(self.manifest)
        session.add_issue(Issue("OPTIONAL_TOOL_MISSING", Severity.WARNING, "brew is unavailable"))
        session.write_report("# Cleanup report\n")

        self.assertEqual(read_json(self.session_path / "inventory.json")["schema_version"], 1)
        self.assertEqual(read_json(self.session_path / "policy.json")["schema_version"], 1)
        self.assertEqual(read_json(self.session_path / "manifest.json"), self.manifest.to_dict())
        self.assertEqual((self.session_path / "report.md").read_text(encoding="utf-8"), "# Cleanup report\n")
        self.assertEqual(session.state["issues"][0]["code"], "OPTIONAL_TOOL_MISSING")
        for artifact in ("inventory.json", "policy.json", "manifest.json", "state.json"):
            self.assertEqual(os.stat(self.session_path / artifact).st_mode & 0o777, 0o600)

    def test_valid_lifecycle_is_persisted_and_terminal_state_cannot_reopen(self) -> None:
        session = Session.create(self.session_path)
        session.write_manifest(self.manifest)

        for status in ("approved", "applied", "verified"):
            session.transition("cache-a", status)

        session.write_manifest(self.manifest)
        self.assertEqual(session.status("cache-a"), "verified")
        with self.assertRaises(InvalidTransition):
            session.transition("cache-a", "applied")

        events = session.state["events"]
        self.assertEqual([(event["from"], event["to"]) for event in events], [
            ("pending", "approved"),
            ("approved", "applied"),
            ("applied", "verified"),
        ])
        self.assertTrue(all(event["at"].endswith("Z") for event in events))

    def test_critical_stop_and_issue_are_latched_atomically_and_reloaded(self) -> None:
        session = Session.create(self.session_path)
        critical = Issue(
            "executor.symlink-or-outside",
            Severity.CRITICAL,
            "unsafe target",
            "cache-a",
        )

        session.latch_critical(critical)
        resumed = Session.load(self.session_path)

        self.assertEqual(resumed.critical_issue(), critical)
        self.assertEqual(resumed.state["critical_stop"]["code"], critical.code)
        self.assertEqual(resumed.state["issues"][-1]["code"], critical.code)

    def test_stale_session_transition_cannot_erase_a_newer_critical_latch(self) -> None:
        session = Session.create(self.session_path)
        session.write_manifest(self.manifest)
        latch_owner = Session.load(self.session_path)
        stale_writer = Session.load(self.session_path)
        critical = Issue(
            "executor.symlink-or-outside",
            Severity.CRITICAL,
            "unsafe target",
            "cache-a",
        )

        latch_owner.latch_critical(critical)
        stale_writer.transition("cache-a", "approved")

        resumed = Session.load(self.session_path)
        self.assertEqual(resumed.critical_issue(), critical)
        self.assertEqual(resumed.status("cache-a"), "approved")
        self.assertEqual(resumed.state["issues"][-1]["code"], critical.code)

    def test_forked_child_acquires_after_locking_parent_exits_abruptly(self) -> None:
        Session.create(self.session_path)
        context = multiprocessing.get_context("fork")
        receiver, sender = context.Pipe(duplex=False)
        holder = context.Process(
            target=_fork_inside_session_lock_and_exit,
            args=(str(self.session_path), sender),
        )
        child_pid: int | None = None
        child_reported = False

        holder.start()
        sender.close()
        try:
            self.assertTrue(receiver.poll(2), "lock holder did not report its child")
            kind, child_pid = receiver.recv()
            self.assertEqual(kind, "child")
            holder.join(timeout=2)
            self.assertFalse(holder.is_alive(), "lock holder did not exit")
            self.assertEqual(holder.exitcode, 0)

            self.assertTrue(
                receiver.poll(2),
                "forked child deadlocked on its inherited session lock",
            )
            outcome = receiver.recv()
            child_reported = True
            self.assertEqual(outcome[0], "acquired", outcome)
        finally:
            receiver.close()
            if holder.is_alive():
                holder.kill()
                holder.join(timeout=2)
            if child_pid is not None and not child_reported:
                try:
                    os.kill(child_pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass

    def test_reload_resumes_once_without_inferring_missing_state_as_success(self) -> None:
        session = Session.create(self.session_path)
        session.write_manifest(self.manifest)
        session.transition("cache-a", "approved")
        del session

        resumed = Session.load(self.session_path)
        resumed.transition("cache-a", "applied")

        self.assertEqual(resumed.status("cache-a"), "applied")
        self.assertEqual(
            [(event["from"], event["to"]) for event in resumed.state["events"]],
            [("pending", "approved"), ("approved", "applied")],
        )
        with self.assertRaises(FileNotFoundError):
            Session.load(self.session_path / "missing")

    def test_reload_recovers_manifest_artifact_after_state_first_interruption(self) -> None:
        session = Session.create(self.session_path)

        def interrupt_manifest_write(path: str | Path, value: object) -> None:
            if Path(path).name == "manifest.json":
                raise OSError("simulated interruption")
            atomic_write_json(path, value)

        with patch("scripts.mac_cleanup.sessions.atomic_write_json", side_effect=interrupt_manifest_write):
            with self.assertRaises(OSError):
                session.write_manifest(self.manifest)
        del session

        resumed = Session.load(self.session_path)

        self.assertEqual(resumed.status("cache-a"), "pending")
        self.assertEqual(read_json(self.session_path / "manifest.json"), self.manifest.to_dict())
        self.assertEqual(resumed.state["manifest"]["target_ids"], ["cache-a"])

    def test_manifest_record_is_isolated_from_caller_mutation(self) -> None:
        session = Session.create(self.session_path)
        manifest = self.manifest.to_dict()
        session.write_manifest(manifest)

        manifest["batches"][0]["targets"][0]["id"] = "poisoned-id"  # type: ignore[index]

        session.transition("cache-a", "approved")
        self.assertEqual(session.status("cache-a"), "approved")

    def test_initial_manifest_write_rejects_unknown_or_omitted_default_fields(self) -> None:
        for name in ("unknown-root", "omitted-status"):
            with self.subTest(name=name):
                session = Session.create(self.session_path / name)
                value = self.manifest.to_dict()
                if name == "unknown-root":
                    value["unrecognized"] = True
                else:
                    del value["batches"][0]["targets"][0]["status"]  # type: ignore[index]

                with self.assertRaises(ValueError):
                    session.write_manifest(value)

                self.assertIsNone(session.state["manifest"])
                self.assertEqual(session.state["targets"], {})
                self.assertFalse(session.manifest_path.exists())

    def test_batch_transition_is_all_or_none_when_state_persistence_is_interrupted(self) -> None:
        second = Target(
            id="cache-b",
            path="/private/tmp/cache-b",
            kind="directory",
            risk=Risk.SAFE_REGENERABLE,
            fingerprint="fingerprint-b",
        )
        session = Session.create(self.session_path)
        session.write_manifest(Manifest(batches=(Batch("safe-caches", (self.target, second)),)))

        def interrupt_state_write(path: str | Path, value: object) -> None:
            if Path(path).name == "state.json":
                raise OSError("simulated interruption")
            atomic_write_json(path, value)

        with patch("scripts.mac_cleanup.sessions.atomic_write_json", side_effect=interrupt_state_write):
            with self.assertRaises(OSError):
                session.transition_batch(("cache-a", "cache-b"), "approved")

        self.assertEqual(session.status("cache-a"), "pending")
        self.assertEqual(session.status("cache-b"), "pending")
        self.assertEqual(session.state["events"], [])
        reloaded = Session.load(self.session_path)
        self.assertEqual(reloaded.state["targets"], {"cache-a": "pending", "cache-b": "pending"})


if __name__ == "__main__":
    unittest.main()
