import fcntl
import multiprocessing
import os
import signal
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.mac_cleanup.jsonio import atomic_write_json, read_json
from scripts.mac_cleanup.models import Batch, Issue, Manifest, Risk, Severity, Target
from scripts.mac_cleanup.sessions import (
    InvalidTransition,
    Session,
    _open_lock_file,
    _same_lock_inode,
)


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


def _load_session_after_reporting_lock_attempt(
    session_path: str, sender: object
) -> None:
    import scripts.mac_cleanup.sessions as sessions_module

    real_flock = sessions_module.fcntl.flock
    reported = False

    def observed_flock(descriptor: int, operation: int) -> None:
        nonlocal reported
        if operation == fcntl.LOCK_EX and not reported:
            reported = True
            sender.send(("waiting", os.fstat(descriptor).st_ino))  # type: ignore[attr-defined]
        real_flock(descriptor, operation)

    sessions_module.fcntl.flock = observed_flock
    try:
        Session.load(session_path)
        current_inode = os.stat(Path(session_path) / ".session.lock").st_ino
        sender.send(("acquired", current_inode))  # type: ignore[attr-defined]
    except BaseException as error:
        sender.send(("error", repr(error)))  # type: ignore[attr-defined]
    finally:
        sender.close()  # type: ignore[attr-defined]


class SessionTest(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.root = Path(self.directory.name).resolve()
        self.session_path = self.root / "session"
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

    def test_create_rejects_noncanonical_or_symlinked_session_paths_before_writing(self) -> None:
        real_parent = self.root / "real-parent"
        real_parent.mkdir(mode=0o700)
        linked_parent = self.root / "linked-parent"
        os.symlink(real_parent, linked_parent)
        targets = (
            Path(str(self.root).replace("/private/var/", "/var/", 1)) / "alias-session",
            linked_parent / "session",
        )

        for target in targets:
            with self.subTest(target=target), self.assertRaises(
                (OSError, ValueError)
            ):
                Session.create(target)

        self.assertEqual(list(real_parent.iterdir()), [])

    def test_create_rejects_unsafe_existing_directory_without_chmod_or_state_write(self) -> None:
        unsafe = self.root / "unsafe-session"
        unsafe.mkdir(mode=0o755)
        sentinel = unsafe / "keep.txt"
        sentinel.write_text("keep", encoding="utf-8")

        with self.assertRaises(ValueError):
            Session.create(unsafe)

        self.assertEqual(os.stat(unsafe).st_mode & 0o777, 0o755)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")
        self.assertFalse((unsafe / "state.json").exists())

    def test_create_rejects_foreign_or_non_directory_session_objects(self) -> None:
        foreign = self.root / "foreign-session"
        foreign.mkdir(mode=0o700)
        regular = self.root / "regular-session"
        regular.write_text("keep", encoding="utf-8")

        with patch(
            "scripts.mac_cleanup.sessions.os.getuid", return_value=os.getuid() + 1
        ), self.assertRaises(ValueError):
            Session.create(foreign)
        with self.assertRaises((NotADirectoryError, ValueError)):
            Session.create(regular)

        self.assertFalse((foreign / "state.json").exists())
        self.assertEqual(regular.read_text(encoding="utf-8"), "keep")

    def test_create_rejects_unsafe_preexisting_lock_without_touching_it(self) -> None:
        for kind in ("symlink", "directory", "mode", "hardlink"):
            with self.subTest(kind=kind):
                session_path = self.root / f"session-{kind}"
                session_path.mkdir(mode=0o700)
                lock_path = session_path / ".session.lock"
                unrelated = self.root / f"unrelated-{kind}"
                unrelated.write_text("keep", encoding="utf-8")
                if kind == "symlink":
                    os.symlink(unrelated, lock_path)
                elif kind == "directory":
                    lock_path.mkdir(mode=0o700)
                elif kind == "mode":
                    lock_path.write_bytes(b"lock")
                    os.chmod(lock_path, 0o644)
                else:
                    os.link(unrelated, lock_path)

                with self.assertRaises((OSError, ValueError)):
                    Session.create(session_path)

                self.assertEqual(unrelated.read_text(encoding="utf-8"), "keep")
                self.assertFalse((session_path / "state.json").exists())

    def test_lock_file_must_share_the_session_directory_device(self) -> None:
        session_path = self.root / "different-device-session"
        session_path.mkdir(mode=0o700)
        lock_path = session_path / ".session.lock"
        lock_path.write_bytes(b"lock")
        os.chmod(lock_path, 0o600)
        directory_descriptor = os.open(session_path, os.O_RDONLY)
        real_fstat = os.fstat

        def different_parent_device(descriptor: int) -> os.stat_result:
            metadata = real_fstat(descriptor)
            if descriptor != directory_descriptor:
                return metadata
            fields = list(metadata)
            fields[2] = metadata.st_dev + 1
            return os.stat_result(fields)

        try:
            with patch(
                "scripts.mac_cleanup.sessions.os.fstat",
                side_effect=different_parent_device,
            ), self.assertRaises(ValueError):
                _open_lock_file(directory_descriptor, create=False)
        finally:
            os.close(directory_descriptor)

        self.assertEqual(lock_path.read_bytes(), b"lock")
        self.assertEqual(os.stat(lock_path).st_mode & 0o777, 0o600)

    def test_locked_inode_metadata_is_revalidated_after_open(self) -> None:
        session = Session.create(self.session_path)
        directory_metadata = os.stat(session.path)
        descriptor = os.open(session.lock_path, os.O_RDWR)
        os.chmod(session.lock_path, 0o640)

        try:
            with self.assertRaises(ValueError):
                _same_lock_inode(
                    session.lock_path,
                    descriptor,
                    (directory_metadata.st_dev, directory_metadata.st_ino),
                )
        finally:
            os.close(descriptor)
            os.chmod(session.lock_path, 0o600)

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

    def test_waiter_retries_current_lock_inode_after_path_replacement(self) -> None:
        Session.create(self.session_path)
        lock_path = self.session_path / ".session.lock"
        old_descriptor = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
        fcntl.flock(old_descriptor, fcntl.LOCK_EX)
        context = multiprocessing.get_context("fork")
        receiver, sender = context.Pipe(duplex=False)
        waiter = context.Process(
            target=_load_session_after_reporting_lock_attempt,
            args=(str(self.session_path), sender),
        )
        new_descriptor = -1

        waiter.start()
        sender.close()
        try:
            self.assertTrue(receiver.poll(2), "waiter never opened the old lock")
            waiting = receiver.recv()
            self.assertEqual(waiting[0], "waiting", waiting)
            replacement = self.session_path / ".replacement.lock"
            replacement.write_bytes(b"")
            os.chmod(replacement, 0o600)
            os.replace(replacement, lock_path)
            new_descriptor = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
            fcntl.flock(new_descriptor, fcntl.LOCK_EX)
            current_inode = os.fstat(new_descriptor).st_ino

            fcntl.flock(old_descriptor, fcntl.LOCK_UN)
            os.close(old_descriptor)
            old_descriptor = -1
            self.assertFalse(
                receiver.poll(0.3),
                "waiter entered through the replaced stale lock inode",
            )

            fcntl.flock(new_descriptor, fcntl.LOCK_UN)
            os.close(new_descriptor)
            new_descriptor = -1
            self.assertTrue(receiver.poll(2), "waiter did not retry the current lock")
            acquired = receiver.recv()
            self.assertEqual(acquired, ("acquired", current_inode))
            waiter.join(timeout=2)
            self.assertEqual(waiter.exitcode, 0)
        finally:
            receiver.close()
            if old_descriptor >= 0:
                fcntl.flock(old_descriptor, fcntl.LOCK_UN)
                os.close(old_descriptor)
            if new_descriptor >= 0:
                fcntl.flock(new_descriptor, fcntl.LOCK_UN)
                os.close(new_descriptor)
            if waiter.is_alive():
                waiter.kill()
                waiter.join(timeout=2)

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
