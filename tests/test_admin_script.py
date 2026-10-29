import fcntl
import json
import multiprocessing
import os
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.mac_cleanup.admin_script import (
    _BOOTSTRAP,
    _VERIFIER_SOURCE,
    generate_admin_script,
    import_admin_results,
    quote_zsh_literal,
    validate_admin_artifacts,
)
from scripts.mac_cleanup.executor import apply_batch
from scripts.mac_cleanup.models import Batch, Issue, Manifest, Risk, Target
from scripts.mac_cleanup.paths import inspect_path
from scripts.mac_cleanup.sessions import Session


def _acquire_verifier_lock_after_reporting_attempt(
    session_path: str, sender: object
) -> None:
    import scripts.mac_cleanup.admin_verifier as verifier

    real_flock = verifier.fcntl.flock
    reported = False

    def observed_flock(descriptor: int, operation: int) -> None:
        nonlocal reported
        if operation == fcntl.LOCK_EX and not reported:
            reported = True
            sender.send(("waiting", os.fstat(descriptor).st_ino))  # type: ignore[attr-defined]
        real_flock(descriptor, operation)

    verifier.fcntl.flock = observed_flock
    session_fd = -1
    lock_fd = -1
    try:
        session_fd = verifier._absolute_directory(session_path, "session")
        owner = os.fstat(session_fd)
        lock_fd = verifier._acquire_stable_lock(
            session_fd, owner.st_uid, owner.st_gid
        )
        sender.send(("acquired", os.fstat(lock_fd).st_ino))  # type: ignore[attr-defined]
    except BaseException as error:
        sender.send(("error", repr(error)))  # type: ignore[attr-defined]
    finally:
        if lock_fd >= 0:
            real_flock(lock_fd, fcntl.LOCK_UN)
            os.close(lock_fd)
        if session_fd >= 0:
            os.close(session_fd)
        sender.close()  # type: ignore[attr-defined]


class AdminScriptTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name).resolve()
        self.home = self.root / "home"
        self.cache_root = self.home / "Library" / "Caches"
        self.cache_root.mkdir(parents=True)
        self.session = Session.create(self.root / "session")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _target(
        self,
        name: str,
        content: bytes = b"cache",
        risk: Risk = Risk.SAFE_REGENERABLE,
    ) -> Target:
        path = self.cache_root / name
        path.mkdir()
        (path / "entry.bin").write_bytes(content)
        identity = inspect_path(path, (self.cache_root,))
        return Target(
            id=f"user-caches:{name}",
            path=identity.canonical,
            kind=identity.kind,
            risk=risk,
            fingerprint=identity.fingerprint,
            logical_bytes=identity.logical_bytes,
        )

    def _register(self, *batches: Batch) -> None:
        self.session.write_manifest(
            Manifest(batches=batches, inventory_digest="a" * 64)
        )
        for batch in batches:
            self.session.transition_batch(
                tuple(target.id for target in batch.targets), "approved"
            )

    def _paths(self, suffix: str = "") -> tuple[Path, Path]:
        return (
            self.session.path / f"admin{suffix}.zsh",
            self.session.path / f"admin-results{suffix}.json",
        )

    def _generate(self, batch: Batch, suffix: str = "") -> tuple[str, Path, Path]:
        script_path, result_path = self._paths(suffix)
        checksum = generate_admin_script(
            batch,
            script_path,
            result_path,
            trusted_home=self.home,
        )
        return checksum, script_path, result_path

    def test_quote_zsh_literal_handles_an_embedded_single_quote(self) -> None:
        self.assertEqual(quote_zsh_literal("a'b"), "'a'\\''b'")

    def test_generated_script_is_static_auditable_and_checksum_is_stable(self) -> None:
        target = self._target("cache with ' quote")
        batch = Batch("safe-user-caches", (target,))
        self._register(batch)

        checksum, script_path, result_path = self._generate(batch)
        first = script_path.read_text(encoding="utf-8")
        repeated = generate_admin_script(
            batch,
            script_path,
            result_path,
            trusted_home=self.home,
        )

        self.assertEqual(checksum, repeated)
        self.assertEqual(first, script_path.read_text(encoding="utf-8"))
        self.assertTrue(first.startswith("#!/bin/zsh\nset -eu\n"))
        self.assertNotIn(quote_zsh_literal(target.path), first)
        for forbidden in (
            "$HOME",
            "${HOME}",
            "$(",
            "`",
            "eval ",
            "chmod -R",
            "chown -R",
        ):
            self.assertNotIn(forbidden, first)
        self.assertNotIn("*", first)
        binding = self.session.state["admin_scripts"][batch.id]
        self.assertEqual(binding["checksum"], checksum)
        self.assertRegex(binding["snapshot_digest"], r"^[0-9a-f]{64}$")
        self.assertEqual(binding["result_path"], str(result_path))

    def test_script_executes_only_the_approved_fixture_target(self) -> None:
        target = self._target("approved")
        sibling = self.cache_root / "preserved"
        sibling.mkdir()
        (sibling / "keep.txt").write_text("keep", encoding="utf-8")
        batch = Batch("safe-user-caches", (target,))
        self._register(batch)
        checksum, script_path, result_path = self._generate(batch)

        completed = subprocess.run(
            (str(script_path),), capture_output=True, text=True, check=False
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse(Path(target.path).exists())
        self.assertEqual((sibling / "keep.txt").read_text(encoding="utf-8"), "keep")
        results = json.loads(result_path.read_text(encoding="utf-8"))
        self.assertEqual(results["targets"][target.id]["status"], "verified")
        import_admin_results(
            self.session,
            result_path,
            checksum,
            trusted_home=self.home,
        )
        self.assertEqual(self.session.status(target.id), "verified")

    def test_generation_rejects_a_forged_approved_target_outside_trusted_cache(self) -> None:
        outside_root = self.root / "outside"
        outside_root.mkdir()
        outside = outside_root / "forged"
        outside.mkdir()
        (outside / "keep.txt").write_text("keep", encoding="utf-8")
        identity = inspect_path(outside, (outside_root,))
        forged = Target(
            id="user-caches:forged",
            path=identity.canonical,
            kind=identity.kind,
            risk=Risk.SAFE_REGENERABLE,
            fingerprint=identity.fingerprint,
            logical_bytes=identity.logical_bytes,
        )
        batch = Batch("safe-user-caches", (forged,))
        self._register(batch)

        with self.assertRaises(ValueError):
            self._generate(batch)

        self.assertTrue(outside.exists())

    def test_generation_requires_exact_approved_session_batch(self) -> None:
        target = self._target("approved")
        batch = Batch("safe-user-caches", (target,))
        self.session.write_manifest(
            Manifest(batches=(batch,), inventory_digest="a" * 64)
        )

        with self.assertRaises(ValueError):
            self._generate(batch)

        self.session.transition(target.id, "approved")
        with self.assertRaises(ValueError):
            self._generate(Batch(batch.id, ()))

    def test_admin_generation_stops_before_artifacts_on_unresolved_intent(self) -> None:
        target = self._target("approved")
        batch = Batch("safe-user-caches", (target,))
        self._register(batch)
        self.session.begin_mutation_intent(
            operation="apply",
            batch_id=batch.id,
            target_id=target.id,
        )
        script_path, result_path = self._paths()

        with self.assertRaisesRegex(ValueError, "unresolved mutation intent"):
            self._generate(batch)

        self.assertFalse(script_path.exists())
        self.assertFalse(result_path.exists())

    def test_changed_identity_stops_script_and_leaves_later_target_untouched(self) -> None:
        changed = self._target("a-changed", b"old")
        later = self._target("b-later")
        batch = Batch("safe-user-caches", (changed, later))
        self._register(batch)
        checksum, script_path, result_path = self._generate(batch)
        (Path(changed.path) / "entry.bin").write_bytes(b"replacement")

        completed = subprocess.run(
            (str(script_path),), capture_output=True, text=True, check=False
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertTrue(Path(changed.path).exists())
        self.assertTrue(Path(later.path).exists())
        results = json.loads(result_path.read_text(encoding="utf-8"))
        self.assertEqual(results["targets"][changed.id]["status"], "suspended")
        self.assertNotIn(later.id, results["targets"])
        import_admin_results(
            self.session,
            result_path,
            checksum,
            trusted_home=self.home,
        )
        self.assertEqual(self.session.status(changed.id), "suspended")
        self.assertEqual(self.session.status(later.id), "suspended")

    def test_missing_results_suspend_only_that_batch(self) -> None:
        completed_target = self._target("a-completed")
        missing_target = self._target("b-missing")
        independent_target = self._target(
            "independent", risk=Risk.REVIEW_REQUIRED
        )
        first = Batch("safe-user-caches", (completed_target, missing_target))
        second = Batch("review-user-caches", (independent_target,))
        self._register(first, second)
        checksum, _, result_path = self._generate(first)
        os.unlink(completed_target.path + "/entry.bin")
        os.rmdir(completed_target.path)
        results = json.loads(result_path.read_text(encoding="utf-8"))
        results["targets"][completed_target.id] = {
            "issues": [],
            "logical_bytes_removed": completed_target.logical_bytes,
            "status": "verified",
        }
        result_path.write_text(json.dumps(results), encoding="utf-8")

        import_admin_results(
            self.session,
            result_path,
            checksum,
            trusted_home=self.home,
        )

        self.assertEqual(self.session.status(completed_target.id), "verified")
        self.assertEqual(self.session.status(missing_target.id), "suspended")
        self.assertEqual(self.session.status(independent_target.id), "approved")

    def test_unknown_target_id_and_checksum_mismatch_are_rejected_without_transition(self) -> None:
        target = self._target("approved")
        batch = Batch("safe-user-caches", (target,))
        self._register(batch)
        checksum, _, result_path = self._generate(batch)
        results = json.loads(result_path.read_text(encoding="utf-8"))
        results["targets"]["user-caches:unknown"] = {
            "issues": [],
            "logical_bytes_removed": 0,
            "status": "verified",
        }
        result_path.write_text(json.dumps(results), encoding="utf-8")

        with self.assertRaises(ValueError):
            import_admin_results(
                self.session,
                result_path,
                checksum,
                trusted_home=self.home,
            )
        with self.assertRaises(ValueError):
            import_admin_results(
                self.session,
                result_path,
                "0" * 64,
                trusted_home=self.home,
            )
        self.assertEqual(self.session.status(target.id), "approved")

    def test_forged_verified_result_cannot_authorize_a_present_target(self) -> None:
        target = self._target("still-present")
        batch = Batch("safe-user-caches", (target,))
        self._register(batch)
        checksum, _, result_path = self._generate(batch)
        results = json.loads(result_path.read_text(encoding="utf-8"))
        results["targets"][target.id] = {
            "issues": [],
            "logical_bytes_removed": target.logical_bytes,
            "status": "verified",
        }
        result_path.write_text(json.dumps(results), encoding="utf-8")

        import_admin_results(
            self.session,
            result_path,
            checksum,
            trusted_home=self.home,
        )

        self.assertTrue(Path(target.path).exists())
        self.assertEqual(self.session.status(target.id), "suspended")

    def test_modified_script_blocks_import(self) -> None:
        target = self._target("approved")
        batch = Batch("safe-user-caches", (target,))
        self._register(batch)
        checksum, script_path, result_path = self._generate(batch)
        original = script_path.read_text(encoding="utf-8")
        script_path.write_text(original + "# changed\n", encoding="utf-8")

        with self.assertRaises(ValueError):
            import_admin_results(
                self.session,
                result_path,
                checksum,
                trusted_home=self.home,
            )
        self.assertEqual(self.session.status(target.id), "approved")

    def test_missing_result_file_suspends_the_bound_batch(self) -> None:
        target = self._target("approved")
        batch = Batch("safe-user-caches", (target,))
        self._register(batch)
        checksum, _, result_path = self._generate(batch)
        result_path.unlink()

        import_admin_results(
            self.session,
            result_path,
            checksum,
            trusted_home=self.home,
        )

        self.assertEqual(self.session.status(target.id), "suspended")

    def test_retry_stops_if_a_previously_removed_target_was_regenerated(self) -> None:
        target = self._target("regenerated")
        later = self._target("z-later")
        batch = Batch("safe-user-caches", (target, later))
        self._register(batch)
        _, script_path, result_path = self._generate(batch)
        (Path(later.path) / "entry.bin").write_bytes(b"changed")
        first = subprocess.run((str(script_path),), check=False)
        self.assertNotEqual(first.returncode, 0)
        self.assertFalse(Path(target.path).exists())
        recreated = Path(target.path)
        recreated.mkdir()
        (recreated / "new.bin").write_bytes(b"new")

        completed = subprocess.run(
            (str(script_path),), capture_output=True, text=True, check=False
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertTrue(recreated.exists())
        self.assertTrue(Path(later.path).exists())
        results = json.loads(result_path.read_text(encoding="utf-8"))
        self.assertEqual(results["targets"][target.id]["status"], "suspended")

    def test_critical_result_latches_session_and_blocks_independent_import(self) -> None:
        unsafe = self._target("unsafe")
        independent = self._target("independent", risk=Risk.REVIEW_REQUIRED)
        first = Batch("safe-user-caches", (unsafe,))
        second = Batch("review-user-caches", (independent,))
        self._register(first, second)
        first_checksum, first_script, first_result = self._generate(first, "-first")
        second_checksum, _, second_result = self._generate(second, "-second")
        unsafe_path = Path(unsafe.path)
        (unsafe_path / "entry.bin").unlink()
        unsafe_path.rmdir()
        os.symlink(self.root, unsafe_path)

        completed = subprocess.run(
            (str(first_script),), capture_output=True, text=True, check=False
        )
        self.assertEqual(completed.returncode, 4)
        import_admin_results(
            self.session,
            first_result,
            first_checksum,
            trusted_home=self.home,
        )

        self.assertIsNotNone(self.session.critical_issue())
        self.assertEqual(self.session.status(independent.id), "approved")
        with self.assertRaises(ValueError):
            import_admin_results(
                self.session,
                second_result,
                second_checksum,
                trusted_home=self.home,
            )
        self.assertTrue(Path(independent.path).exists())

    def test_latch_written_while_script_waits_for_session_lock_stops_deletion(self) -> None:
        target = self._target("lock-waiter")
        batch = Batch("safe-user-caches", (target,))
        self._register(batch)
        _, script_path, _ = self._generate(batch)
        process: subprocess.Popen[str] | None = None

        with self.session.operation_lock():
            process = subprocess.Popen(
                (str(script_path),),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            critical = {
                "code": "test.critical",
                "severity": "critical",
                "message": "stop before fallback",
                "target_id": target.id,
            }
            self.session.latch_critical(Issue.from_dict(critical))

        assert process is not None
        _, stderr = process.communicate(timeout=5)
        self.assertNotEqual(process.returncode, 0, stderr)
        self.assertTrue(Path(target.path).exists())
        self.assertEqual(self.session.status(target.id), "approved")

    def test_status_change_while_script_waits_for_lock_stops_deletion(self) -> None:
        target = self._target("status-race")
        batch = Batch("safe-user-caches", (target,))
        self._register(batch)
        _, script_path, _ = self._generate(batch)

        with self.session.operation_lock():
            process = subprocess.Popen(
                (str(script_path),),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            self.session.transition(target.id, "applied")

        _, stderr = process.communicate(timeout=5)
        self.assertNotEqual(process.returncode, 0, stderr)
        self.assertTrue(Path(target.path).exists())
        self.assertEqual(self.session.status(target.id), "applied")

    def test_direct_apply_serializes_with_generated_execution(self) -> None:
        target = self._target("direct-race")
        batch = Batch("safe-user-caches", (target,))
        self._register(batch)
        _, script_path, result_path = self._generate(batch)

        with self.session.operation_lock():
            process = subprocess.Popen(
                (str(script_path),),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            outcome = apply_batch(self.session, batch, (self.cache_root,))

        _, stderr = process.communicate(timeout=5)
        self.assertFalse(outcome.suspended)
        self.assertNotEqual(process.returncode, 0, stderr)
        self.assertFalse(Path(target.path).exists())
        self.assertEqual(self.session.status(target.id), "verified")
        results = json.loads(result_path.read_text(encoding="utf-8"))
        self.assertEqual(results["targets"], {})

    def test_isolated_python_ignores_hostile_cwd_and_sitecustomize(self) -> None:
        target = self._target("isolated")
        batch = Batch("safe-user-caches", (target,))
        self._register(batch)
        _, script_path, _ = self._generate(batch)
        hostile = self.root / "hostile"
        hostile.mkdir()
        marker = hostile / "marker"
        payload = (
            "from pathlib import Path\n"
            f"Path({str(marker)!r}).write_text('executed', encoding='utf-8')\n"
            "raise RuntimeError('hostile module loaded')\n"
        )
        for name in ("hashlib.py", "pathlib.py", "sitecustomize.py"):
            (hostile / name).write_text(payload, encoding="utf-8")

        completed = subprocess.run(
            (str(script_path),),
            cwd=hostile,
            capture_output=True,
            text=True,
            check=False,
        )

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertFalse(marker.exists())
        self.assertFalse(Path(target.path).exists())
        script = script_path.read_text(encoding="utf-8")
        self.assertIn("'-I' '-S'", script)

    def test_authentic_bootstrap_rejects_appended_script_tamper(self) -> None:
        target = self._target("script-tamper")
        batch = Batch("safe-user-caches", (target,))
        self._register(batch)
        _, script_path, _ = self._generate(batch)
        script_path.write_text(
            script_path.read_text(encoding="utf-8") + "# tampered\n",
            encoding="utf-8",
        )
        os.chmod(script_path, 0o700)

        completed = subprocess.run(
            (str(script_path),), capture_output=True, text=True, check=False
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertTrue(Path(target.path).exists())

    def test_authentic_bootstrap_rejects_divergent_durable_checksum(self) -> None:
        target = self._target("binding-tamper")
        batch = Batch("safe-user-caches", (target,))
        self._register(batch)
        _, script_path, _ = self._generate(batch)
        state_path = self.session.state_path
        state = json.loads(state_path.read_text(encoding="utf-8"))
        state["admin_scripts"][batch.id]["checksum"] = "0" * 64
        state_path.write_text(json.dumps(state), encoding="utf-8")

        completed = subprocess.run(
            (str(script_path),), capture_output=True, text=True, check=False
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertTrue(Path(target.path).exists())

    def test_result_mode_anomaly_fails_before_mutation(self) -> None:
        target = self._target("mode-result")
        batch = Batch("safe-user-caches", (target,))
        self._register(batch)
        _, script_path, result_path = self._generate(batch)
        os.chmod(result_path, 0o644)

        completed = subprocess.run(
            (str(script_path),), capture_output=True, text=True, check=False
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertTrue(Path(target.path).exists())

    def test_malformed_existing_result_fails_before_mutation(self) -> None:
        target = self._target("malformed-result")
        batch = Batch("safe-user-caches", (target,))
        self._register(batch)
        _, script_path, result_path = self._generate(batch)
        results = json.loads(result_path.read_text(encoding="utf-8"))
        results["targets"][target.id] = {"status": "verified"}
        result_path.write_text(json.dumps(results), encoding="utf-8")

        completed = subprocess.run(
            (str(script_path),), capture_output=True, text=True, check=False
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertTrue(Path(target.path).exists())

    def test_snapshot_mode_anomaly_fails_before_mutation(self) -> None:
        target = self._target("mode-snapshot")
        batch = Batch("safe-user-caches", (target,))
        self._register(batch)
        _, script_path, _ = self._generate(batch)
        binding = self.session.state["admin_scripts"][batch.id]
        os.chmod(Path(binding["snapshot_path"]), 0o644)

        completed = subprocess.run(
            (str(script_path),), capture_output=True, text=True, check=False
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertTrue(Path(target.path).exists())

    def test_authentic_script_rejects_snapshot_only_tamper(self) -> None:
        target = self._target("snapshot-tamper")
        batch = Batch("safe-user-caches", (target,))
        self._register(batch)
        _, script_path, _ = self._generate(batch)
        binding = self.session.state["admin_scripts"][batch.id]
        snapshot = Path(binding["snapshot_path"])
        snapshot.write_text(
            snapshot.read_text(encoding="utf-8") + "# tampered\n",
            encoding="utf-8",
        )

        completed = subprocess.run(
            (str(script_path),), capture_output=True, text=True, check=False
        )

        self.assertNotEqual(completed.returncode, 0)
        self.assertTrue(Path(target.path).exists())

    def test_engine_validation_returns_exact_artifact_identity(self) -> None:
        target = self._target("validated")
        batch = Batch("safe-user-caches", (target,))
        self._register(batch)
        checksum, script_path, _ = self._generate(batch)
        binding = self.session.state["admin_scripts"][batch.id]

        validation = validate_admin_artifacts(
            self.session, batch.id, trusted_home=self.home
        )

        self.assertEqual(validation.batch_id, batch.id)
        self.assertEqual(validation.checksum, checksum)
        self.assertEqual(validation.script_path, script_path)
        self.assertEqual(validation.snapshot_path, Path(binding["snapshot_path"]))
        self.assertEqual(validation.snapshot_digest, binding["snapshot_digest"])
        self.assertEqual(validation.manifest_digest, binding["manifest_digest"])
        self.assertTrue(Path(target.path).exists())

    def test_generation_runs_engine_validation_after_publishing_artifacts(self) -> None:
        target = self._target("generation-validation")
        batch = Batch("safe-user-caches", (target,))
        self._register(batch)

        with patch(
            "scripts.mac_cleanup.admin_script.validate_admin_artifacts",
            wraps=validate_admin_artifacts,
        ) as validator:
            checksum, _, _ = self._generate(batch)

        validator.assert_called_once()
        called_session, called_batch_id = validator.call_args.args
        self.assertEqual(called_session.path, self.session.path)
        self.assertEqual(called_batch_id, batch.id)
        self.assertEqual(validator.call_args.kwargs, {"trusted_home": self.home})
        self.assertRegex(checksum, r"^[0-9a-f]{64}$")

    def test_engine_validation_and_import_reject_wholesale_artifact_replacement(
        self,
    ) -> None:
        target = self._target("wholesale-replacement")
        batch = Batch("safe-user-caches", (target,))
        self._register(batch)
        checksum, script_path, result_path = self._generate(batch)
        binding = self.session.state["admin_scripts"][batch.id]
        snapshot = Path(binding["snapshot_path"])
        script_path.write_text("#!/bin/zsh\necho arbitrary-code\n", encoding="utf-8")
        snapshot.write_text("raise SystemExit('arbitrary-code')\n", encoding="utf-8")
        os.chmod(script_path, 0o700)
        os.chmod(snapshot, 0o600)

        with self.assertRaises(ValueError):
            validate_admin_artifacts(
                self.session, batch.id, trusted_home=self.home
            )
        with self.assertRaises(ValueError):
            import_admin_results(
                self.session,
                result_path,
                checksum,
                trusted_home=self.home,
            )

        self.assertTrue(Path(target.path).exists())
        self.assertEqual(self.session.status(target.id), "approved")

    def test_snapshot_is_self_contained_and_result_preserves_session_owner(self) -> None:
        target = self._target("owned")
        batch = Batch("safe-user-caches", (target,))
        self._register(batch)
        _, script_path, result_path = self._generate(batch)
        binding = self.session.state["admin_scripts"][batch.id]
        snapshot = Path(binding["snapshot_path"])
        snapshot_text = snapshot.read_text(encoding="utf-8")

        self.assertEqual(snapshot_text, _VERIFIER_SOURCE)
        self.assertNotIn("scripts.mac_cleanup", snapshot_text)
        self.assertNotIn("sys.path", snapshot_text)
        completed = subprocess.run((str(script_path),), check=False)
        self.assertEqual(completed.returncode, 0)
        session_stat = self.session.path.stat()
        result_stat = result_path.stat()
        self.assertEqual(result_stat.st_uid, session_stat.st_uid)
        self.assertEqual(result_stat.st_gid, session_stat.st_gid)
        self.assertEqual(result_stat.st_mode & 0o777, 0o600)

    def test_bootstrap_executes_only_the_once_read_verified_snapshot_bytes(self) -> None:
        self.assertIn("state.json", _BOOTSTRAP)
        self.assertIn('binding["checksum"]', _BOOTSTRAP)
        self.assertIn('binding["snapshot_digest"]', _BOOTSTRAP)
        self.assertIn("snapshot_bytes=read_regular_at", _BOOTSTRAP)
        self.assertIn("exec(compile(snapshot_bytes", _BOOTSTRAP)
        self.assertLess(
            _BOOTSTRAP.index("state.json"),
            _BOOTSTRAP.index('binding["checksum"]'),
        )
        self.assertLess(
            _BOOTSTRAP.index('binding["checksum"]'),
            _BOOTSTRAP.index("snapshot_bytes=read_regular_at"),
        )
        self.assertLess(
            _BOOTSTRAP.index("snapshot_bytes=read_regular_at"),
            _BOOTSTRAP.index("exec(compile(snapshot_bytes"),
        )
        self.assertNotIn("read_bytes", _BOOTSTRAP)

    def test_generated_script_does_not_embed_durable_artifact_digests(self) -> None:
        target = self._target("durable-only")
        batch = Batch("safe-user-caches", (target,))
        self._register(batch)
        checksum, script_path, _ = self._generate(batch)
        binding = self.session.state["admin_scripts"][batch.id]
        script = script_path.read_text(encoding="utf-8")

        self.assertNotIn(checksum, script)
        self.assertNotIn(binding["snapshot_digest"], script)
        self.assertNotIn(binding["snapshot_path"], script)

    def test_verifier_waiter_retries_current_lock_inode_after_replacement(self) -> None:
        lock_path = self.session.path / ".session.lock"
        old_descriptor = os.open(lock_path, os.O_RDWR | os.O_NOFOLLOW)
        fcntl.flock(old_descriptor, fcntl.LOCK_EX)
        context = multiprocessing.get_context("fork")
        receiver, sender = context.Pipe(duplex=False)
        waiter = context.Process(
            target=_acquire_verifier_lock_after_reporting_attempt,
            args=(str(self.session.path), sender),
        )
        new_descriptor = -1

        waiter.start()
        sender.close()
        try:
            self.assertTrue(receiver.poll(2), "verifier never opened the old lock")
            self.assertEqual(receiver.recv()[0], "waiting")
            replacement = self.session.path / ".replacement.lock"
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
                "verifier entered through the replaced stale lock inode",
            )

            fcntl.flock(new_descriptor, fcntl.LOCK_UN)
            os.close(new_descriptor)
            new_descriptor = -1
            self.assertTrue(receiver.poll(2), "verifier did not retry current lock")
            self.assertEqual(receiver.recv(), ("acquired", current_inode))
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

    def test_snapshot_privileged_writer_fchowns_temp_to_bound_owner(self) -> None:
        namespace = {"__name__": "verifier_test"}
        exec(compile(_VERIFIER_SOURCE, "<verifier>", "exec"), namespace)
        calls: list[tuple[int, int]] = []
        real_fchown = os.fchown

        def record_fchown(descriptor: int, uid: int, gid: int) -> None:
            calls.append((uid, gid))
            real_fchown(descriptor, os.getuid(), os.getgid())

        destination = self.session.path / "owner-simulation.json"
        with patch.object(namespace["os"], "geteuid", return_value=0), patch.object(
            namespace["os"], "fchown", side_effect=record_fchown
        ):
            namespace["_atomic_write_json_owned"](
                str(destination), {"ok": True}, os.getuid(), os.getgid()
            )

        self.assertIn((os.getuid(), os.getgid()), calls)
        self.assertEqual(destination.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
