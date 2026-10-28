import os
import fcntl
import multiprocessing
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.mac_cleanup.executor import apply_batch, preflight_target, verify_batch
from scripts.mac_cleanup.models import Batch, Issue, Manifest, Risk, Severity, Target
from scripts.mac_cleanup.paths import PathSafetyError, inspect_path, remove_tree_exact
from scripts.mac_cleanup.sessions import Session


def _apply_in_forked_process(
    session_path: str,
    batch_id: str,
    allowed_root: str,
    attempted: object,
    results: object,
) -> None:
    attempted.set()  # type: ignore[attr-defined]
    session = Session.load(session_path)
    batch = next(
        candidate
        for candidate in session.read_manifest().batches
        if candidate.id == batch_id
    )
    outcome = apply_batch(session, batch, (allowed_root,))
    results.put(  # type: ignore[attr-defined]
        {
            "critical": any(
                issue.severity is Severity.CRITICAL for issue in outcome.issues
            ),
            "suspended": outcome.suspended,
        }
    )


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
        outcome = apply_batch(self.session, batch, (self.allowed_root,))

        self.assertTrue(Path(valid.path).exists())
        self.assertEqual(
            (protected / "important.txt").read_text(encoding="utf-8"), "keep"
        )
        self.assertIn(Severity.CRITICAL, {issue.severity for issue in outcome.issues})
        resumed = Session.load(self.session.path)
        self.assertEqual(
            resumed.critical_issue().code, "executor.symlink-or-outside"
        )
        self.assertEqual(resumed.state["issues"][-1]["severity"], "critical")

    def test_critical_latch_blocks_a_future_independent_batch(self) -> None:
        replaced = self._target("cache-a")
        independent = self._target("cache-b")
        first = Batch("safe-a", (replaced,))
        second = Batch("safe-b", (independent,))
        self._write_and_approve(first, second)
        replaced_path = Path(replaced.path)
        (replaced_path / "entry.bin").unlink()
        replaced_path.rmdir()
        os.symlink(self.root, replaced_path)

        apply_batch(self.session, first, (self.allowed_root,))
        resumed = Session.load(self.session.path)
        outcome = apply_batch(resumed, second, (self.allowed_root,))

        self.assertIn(Severity.CRITICAL, {issue.severity for issue in outcome.issues})
        self.assertTrue(Path(independent.path).exists())
        self.assertEqual(resumed.status(independent.id), "approved")

    def test_stale_sessions_cannot_apply_or_verify_after_newer_latch(self) -> None:
        critical_target = self._target("cache-a")
        apply_target = self._target("cache-b")
        verify_target = self._target("cache-c")
        first = Batch("safe-a", (critical_target,))
        second = Batch("safe-b", (apply_target,))
        third = Batch("safe-c", (verify_target,))
        self._write_and_approve(first, second, third)
        self.session.transition(verify_target.id, "applied")
        latch_owner = Session.load(self.session.path)
        stale_dry_run = Session.load(self.session.path)
        stale_apply = Session.load(self.session.path)
        stale_verify = Session.load(self.session.path)
        critical = Issue(
            "executor.symlink-or-outside",
            Severity.CRITICAL,
            "unsafe target",
            critical_target.id,
        )

        latch_owner.latch_critical(critical)
        dry_run_outcome = apply_batch(
            stale_dry_run, second, (self.allowed_root,), dry_run=True
        )
        apply_outcome = apply_batch(stale_apply, second, (self.allowed_root,))
        verify_outcome = verify_batch(stale_verify, third, (self.allowed_root,))

        resumed = Session.load(self.session.path)
        self.assertEqual(resumed.critical_issue(), critical)
        self.assertTrue(dry_run_outcome.dry_run)
        self.assertIn(Severity.CRITICAL, {i.severity for i in dry_run_outcome.issues})
        self.assertIn(Severity.CRITICAL, {i.severity for i in apply_outcome.issues})
        self.assertIn(Severity.CRITICAL, {i.severity for i in verify_outcome.issues})
        self.assertTrue(Path(apply_target.path).exists())
        self.assertTrue(Path(verify_target.path).exists())
        self.assertEqual(resumed.status(apply_target.id), "approved")
        self.assertEqual(resumed.status(verify_target.id), "applied")

    def test_operation_lock_serializes_interleaved_apply_before_latch_check(self) -> None:
        critical_target = self._target("cache-a")
        apply_target = self._target("cache-b")
        first = Batch("safe-a", (critical_target,))
        second = Batch("safe-b", (apply_target,))
        self._write_and_approve(first, second)
        latch_owner = Session.load(self.session.path)
        concurrent = Session.load(self.session.path)
        attempted = threading.Event()
        completed = threading.Event()
        outcomes = []
        errors = []

        def run_apply() -> None:
            attempted.set()
            try:
                outcomes.append(
                    apply_batch(concurrent, second, (self.allowed_root,))
                )
            except BaseException as error:
                errors.append(error)
            finally:
                completed.set()

        critical = Issue(
            "executor.symlink-or-outside",
            Severity.CRITICAL,
            "unsafe target",
            critical_target.id,
        )
        with latch_owner.operation_lock():
            worker = threading.Thread(target=run_apply)
            worker.start()
            self.assertTrue(attempted.wait(timeout=1))
            latch_owner.latch_critical(critical)
        self.assertTrue(completed.wait(timeout=2))
        worker.join(timeout=2)

        self.assertEqual(errors, [])
        self.assertEqual(len(outcomes), 1)
        self.assertIn(Severity.CRITICAL, {i.severity for i in outcomes[0].issues})
        self.assertTrue(Path(apply_target.path).exists())
        self.assertEqual(Session.load(self.session.path).critical_issue(), critical)

    def test_forked_apply_reloads_latch_after_interprocess_lock_acquisition(self) -> None:
        critical_target = self._target("cache-a")
        apply_target = self._target("cache-b")
        first = Batch("safe-a", (critical_target,))
        second = Batch("safe-b", (apply_target,))
        self._write_and_approve(first, second)
        latch_owner = Session.load(self.session.path)
        context = multiprocessing.get_context("fork")
        attempted = context.Event()
        results = context.Queue()
        critical = Issue(
            "executor.symlink-or-outside",
            Severity.CRITICAL,
            "unsafe target",
            critical_target.id,
        )

        with latch_owner.operation_lock():
            worker = context.Process(
                target=_apply_in_forked_process,
                args=(
                    str(self.session.path),
                    second.id,
                    str(self.allowed_root),
                    attempted,
                    results,
                ),
            )
            worker.start()
            self.assertTrue(attempted.wait(timeout=2))
            latch_owner.latch_critical(critical)
        worker.join(timeout=5)

        self.assertEqual(worker.exitcode, 0)
        self.assertEqual(results.get(timeout=1), {"critical": True, "suspended": True})
        self.assertTrue(Path(apply_target.path).exists())
        self.assertEqual(Session.load(self.session.path).critical_issue(), critical)

    def test_critical_dry_run_reports_without_latching_or_transitioning(self) -> None:
        replaced = self._target("cache-a")
        batch = Batch("safe-a", (replaced,))
        self._write_and_approve(batch)
        replaced_path = Path(replaced.path)
        (replaced_path / "entry.bin").unlink()
        replaced_path.rmdir()
        os.symlink(self.root, replaced_path)
        state_before = self.session.state

        outcome = apply_batch(
            self.session, batch, (self.allowed_root,), dry_run=True
        )

        self.assertIn(Severity.CRITICAL, {issue.severity for issue in outcome.issues})
        self.assertEqual(self.session.state, state_before)
        self.assertIsNone(self.session.critical_issue())

    def test_runtime_critical_is_latched_before_returning(self) -> None:
        target = self._target("cache-a")
        batch = Batch("safe-a", (target,))
        self._write_and_approve(batch)

        with patch(
            "scripts.mac_cleanup.executor.remove_tree_exact",
            side_effect=PathSafetyError("symlinks are not allowed"),
        ):
            outcome = apply_batch(self.session, batch, (self.allowed_root,))

        self.assertIn(Severity.CRITICAL, {issue.severity for issue in outcome.issues})
        self.assertEqual(
            Session.load(self.session.path).critical_issue().code,
            "executor.symlink-or-outside",
        )
        self.assertTrue(Path(target.path).exists())

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

    def test_recreated_verified_target_is_informational_and_never_reapplied(self) -> None:
        target = self._target("cache-a")
        batch = Batch("safe-a", (target,))
        self._write_and_approve(batch)
        apply_batch(self.session, batch, (self.allowed_root,))
        recreated = Path(target.path)
        recreated.mkdir()
        content = b"regenerated-cache"
        (recreated / "entry.bin").write_bytes(content)

        verified = verify_batch(self.session, batch, (self.allowed_root,))
        applied_again = apply_batch(self.session, batch, (self.allowed_root,))

        self.assertEqual(self.session.status(target.id), "verified")
        self.assertTrue(recreated.exists())
        self.assertEqual(verified.regenerated_target_ids, (target.id,))
        self.assertEqual(verified.regenerated_bytes, len(content))
        self.assertEqual(verified.issues[0].code, "executor.target-regenerated")
        self.assertEqual(verified.issues[0].severity, Severity.INFORMATIONAL)
        self.assertEqual(applied_again.regenerated_target_ids, (target.id,))
        self.assertEqual(applied_again.regenerated_bytes, len(content))

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

    def test_interrupted_exact_removal_marks_target_and_batch_accounting_unknown(self) -> None:
        target = self._target("cache-a", b"first")
        second_entry = Path(target.path) / "second.bin"
        second_entry.write_bytes(b"second")
        refreshed = inspect_path(target.path, (self.allowed_root,))
        target = Target(
            id=target.id,
            path=refreshed.canonical,
            kind=refreshed.kind,
            risk=target.risk,
            fingerprint=refreshed.fingerprint,
            logical_bytes=refreshed.logical_bytes,
        )
        batch = Batch("safe-a", (target,))
        self._write_and_approve(batch)

        def remove_one_then_fail(identity: object, roots: object) -> int:
            del identity, roots
            (Path(target.path) / "entry.bin").unlink()
            raise OSError("simulated interruption after partial deletion")

        with patch(
            "scripts.mac_cleanup.executor.remove_tree_exact",
            side_effect=remove_one_then_fail,
        ):
            outcome = apply_batch(self.session, batch, (self.allowed_root,))

        self.assertIsNone(outcome.logical_bytes_removed)
        self.assertEqual(outcome.logical_bytes_removed_by_target, ())
        self.assertEqual(outcome.uncertain_target_ids, (target.id,))
        self.assertTrue(outcome.suspended)
        self.assertFalse((Path(target.path) / "entry.bin").exists())
        self.assertTrue(second_entry.exists())
        self.assertEqual(self.session.status(target.id), "suspended")
        self.assertIn(
            "executor.removal-accounting-uncertain",
            {issue.code for issue in outcome.issues},
        )

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
