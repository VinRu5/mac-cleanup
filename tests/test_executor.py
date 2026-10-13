import os
import fcntl
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.mac_cleanup.executor import apply_batch, preflight_target, verify_batch
from scripts.mac_cleanup.models import Batch, Manifest, Risk, Severity, Target
from scripts.mac_cleanup.paths import PathSafetyError, inspect_path, remove_tree_exact
from scripts.mac_cleanup.sessions import Session


class ExecutorTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary_directory = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary_directory.name).resolve()
        self.allowed_root = self.root / "allowed"
        self.allowed_root.mkdir()
        self.session = Session.create(self.root / "session")

    def tearDown(self) -> None:
        self.temporary_directory.cleanup()

    def _target(self, target_id: str, content: bytes = b"cache") -> Target:
        path = self.allowed_root / target_id
        path.mkdir()
        (path / "entry.bin").write_bytes(content)
        identity = inspect_path(path, (self.allowed_root,))
        return Target(
            id=target_id,
            path=identity.canonical,
            kind=identity.kind,
            risk=Risk.SAFE_REGENERABLE,
            fingerprint=identity.fingerprint,
            logical_bytes=identity.logical_bytes,
        )

    def _write_and_approve(self, *batches: Batch) -> None:
        self.session.write_manifest(
            Manifest(batches=batches, inventory_digest="a" * 64)
        )
        for batch in batches:
            self.session.transition_batch(
                tuple(target.id for target in batch.targets), "approved"
            )

    def test_unchanged_approved_batch_is_deleted_and_verified(self) -> None:
        target = self._target("cache-a")
        batch = Batch("safe-a", (target,))
        self._write_and_approve(batch)

        outcome = apply_batch(self.session, batch, (self.allowed_root,))

        self.assertFalse(Path(target.path).exists())
        self.assertEqual(self.session.status(target.id), "verified")
        self.assertEqual(outcome.logical_bytes_removed, target.logical_bytes)
        self.assertIsNotNone(outcome.free_space_before)
        self.assertIsNotNone(outcome.free_space_after)

    def test_absent_target_is_informational_verified_success(self) -> None:
        target = self._target("cache-a")
        batch = Batch("safe-a", (target,))
        self._write_and_approve(batch)
        path = Path(target.path)
        (path / "entry.bin").unlink()
        path.rmdir()

        issues = preflight_target(target, (self.allowed_root,))
        outcome = apply_batch(self.session, batch, (self.allowed_root,))

        self.assertEqual([(issue.code, issue.severity) for issue in issues], [
            ("executor.target-absent", Severity.INFORMATIONAL),
        ])
        self.assertEqual(self.session.status(target.id), "verified")
        self.assertEqual(outcome.logical_bytes_removed, 0)

    def test_changed_fingerprint_suspends_the_whole_batch_without_deletion(self) -> None:
        changed = self._target("cache-a", b"old")
        unchanged = self._target("cache-b")
        batch = Batch("safe-a", (changed, unchanged))
        self._write_and_approve(batch)
        (Path(changed.path) / "entry.bin").write_bytes(b"replacement")

        outcome = apply_batch(self.session, batch, (self.allowed_root,))

        self.assertTrue(Path(changed.path).exists())
        self.assertTrue(Path(unchanged.path).exists())
        self.assertEqual(self.session.status(changed.id), "suspended")
        self.assertEqual(self.session.status(unchanged.id), "suspended")
        self.assertEqual(outcome.issues[0].severity, Severity.BATCH_ERROR)

    def test_symlink_replacement_is_critical_and_blocks_every_mutation(self) -> None:
        valid = self._target("cache-a")
        replaced = self._target("cache-b")
        batch = Batch("safe-a", (valid, replaced))
        self._write_and_approve(batch)
        protected = self.root / "protected"
        protected.mkdir()
        (protected / "important.txt").write_text("keep", encoding="utf-8")
        replaced_path = Path(replaced.path)
        (replaced_path / "entry.bin").unlink()
        replaced_path.rmdir()
        os.symlink(protected, replaced_path)
        state_before = self.session.state

        outcome = apply_batch(self.session, batch, (self.allowed_root,))

        self.assertTrue(Path(valid.path).exists())
        self.assertEqual(
            (protected / "important.txt").read_text(encoding="utf-8"), "keep"
        )
        self.assertEqual(self.session.state, state_before)
        self.assertIn(Severity.CRITICAL, {issue.severity for issue in outcome.issues})

    def test_batch_error_does_not_change_an_independent_batch(self) -> None:
        changed = self._target("cache-a", b"old")
        independent = self._target("cache-b")
        first = Batch("safe-a", (changed,))
        second = Batch("safe-b", (independent,))
        self._write_and_approve(first, second)
        (Path(changed.path) / "entry.bin").write_bytes(b"replacement")

        first_outcome = apply_batch(self.session, first, (self.allowed_root,))
        second_outcome = apply_batch(self.session, second, (self.allowed_root,))

        self.assertTrue(first_outcome.suspended)
        self.assertEqual(self.session.status(changed.id), "suspended")
        self.assertEqual(self.session.status(independent.id), "verified")
        self.assertFalse(Path(independent.path).exists())
        self.assertFalse(second_outcome.suspended)

    def test_second_apply_is_idempotent(self) -> None:
        target = self._target("cache-a")
        batch = Batch("safe-a", (target,))
        self._write_and_approve(batch)
        first = apply_batch(self.session, batch, (self.allowed_root,))
        state_after_first = self.session.state

        second = apply_batch(self.session, batch, (self.allowed_root,))

        self.assertEqual(self.session.state, state_after_first)
        self.assertEqual(first.logical_bytes_removed, target.logical_bytes)
        self.assertEqual(second.logical_bytes_removed, 0)
        self.assertEqual(self.session.status(target.id), "verified")

    def test_all_targets_are_preflighted_before_first_removal(self) -> None:
        first = self._target("cache-a")
        second = self._target("cache-b")
        batch = Batch("safe-a", (first, second))
        self._write_and_approve(batch)

        with patch(
            "scripts.mac_cleanup.executor.inspect_path",
            wraps=inspect_path,
        ) as inspected:
            apply_batch(self.session, batch, (self.allowed_root,), dry_run=True)

        self.assertEqual(inspected.call_count, 2)
        self.assertTrue(Path(first.path).exists())
        self.assertTrue(Path(second.path).exists())

    def test_target_disappearing_during_preflight_is_informational(self) -> None:
        target = self._target("cache-a")

        def disappeared(*args: object, **kwargs: object) -> object:
            del args, kwargs
            try:
                raise FileNotFoundError(target.path)
            except FileNotFoundError as cause:
                raise PathSafetyError("cannot inspect target") from cause

        with patch("scripts.mac_cleanup.executor.inspect_path", side_effect=disappeared):
            issues = preflight_target(target, (self.allowed_root,))

        self.assertEqual([(issue.code, issue.severity) for issue in issues], [
            ("executor.target-absent", Severity.INFORMATIONAL),
        ])

    def test_completed_target_is_checkpointed_before_a_later_apply_failure(self) -> None:
        first = self._target("cache-a")
        second = self._target("cache-b")
        batch = Batch("safe-a", (first, second))
        self._write_and_approve(batch)

        def fail_second(identity: object, roots: object) -> int:
            if getattr(identity, "canonical") == second.path:
                raise PathSafetyError("target changed since inspection")
            return remove_tree_exact(identity, roots)  # type: ignore[arg-type]

        with patch(
            "scripts.mac_cleanup.executor.remove_tree_exact", side_effect=fail_second
        ):
            outcome = apply_batch(self.session, batch, (self.allowed_root,))

        self.assertTrue(outcome.suspended)
        self.assertEqual(self.session.status(first.id), "verified")
        self.assertEqual(self.session.status(second.id), "suspended")
        self.assertFalse(Path(first.path).exists())
        self.assertTrue(Path(second.path).exists())

    def test_dry_run_has_no_state_transition_or_filesystem_mutation(self) -> None:
        target = self._target("cache-a")
        batch = Batch("safe-a", (target,))
        self._write_and_approve(batch)
        state_before = self.session.state

        outcome = apply_batch(
            self.session, batch, (self.allowed_root,), dry_run=True
        )

        self.assertTrue(outcome.dry_run)
        self.assertTrue(Path(target.path).exists())
        self.assertEqual(self.session.state, state_before)

    def test_in_use_decision_suspends_the_batch(self) -> None:
        target = self._target("cache-a")
        batch = Batch("safe-a", (target,))
        self._write_and_approve(batch)

        with patch("scripts.mac_cleanup.executor._target_in_use", return_value=True):
            outcome = apply_batch(self.session, batch, (self.allowed_root,))

        self.assertTrue(Path(target.path).exists())
        self.assertEqual(self.session.status(target.id), "suspended")
        self.assertEqual(outcome.issues[0].code, "executor.target-in-use")

    def test_advisory_lock_is_detected_as_in_use(self) -> None:
        target = self._target("cache-a")
        batch = Batch("safe-a", (target,))
        self._write_and_approve(batch)
        descriptor = os.open(target.path, os.O_RDONLY | os.O_DIRECTORY)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)

            outcome = apply_batch(self.session, batch, (self.allowed_root,))
        finally:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            os.close(descriptor)

        self.assertTrue(Path(target.path).exists())
        self.assertEqual(self.session.status(target.id), "suspended")
        self.assertEqual(outcome.issues[0].code, "executor.target-in-use")

    def test_verify_requires_explicit_absence_before_verified(self) -> None:
        target = self._target("cache-a")
        batch = Batch("safe-a", (target,))
        self._write_and_approve(batch)
        self.session.transition(target.id, "applied")

        present = verify_batch(self.session, batch, (self.allowed_root,))

        self.assertTrue(present.suspended)
        self.assertEqual(self.session.status(target.id), "suspended")

    def test_rejects_a_batch_not_equal_to_the_named_session_batch(self) -> None:
        target = self._target("cache-a")
        persisted = Batch("safe-a", (target,))
        self._write_and_approve(persisted)
        forged = Batch("safe-a", ())

        with self.assertRaises(ValueError):
            apply_batch(self.session, forged, (self.allowed_root,))


if __name__ == "__main__":
    unittest.main()
