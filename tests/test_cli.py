import tempfile
import unittest
import json
import io
import os
import runpy
import copy
import subprocess
import threading
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

from scripts.mac_cleanup.executor import BatchOutcome, apply_batch as engine_apply_batch
from scripts.mac_cleanup.cli import _plan, _scan, _scan_result, build_parser, main
from scripts.mac_cleanup.jsonio import atomic_write_json, read_json
from scripts.mac_cleanup.manifests import approval_digest, build_manifest
from scripts.mac_cleanup.models import Batch, Issue, Manifest, Risk, Severity, Target
from scripts.mac_cleanup.modules.base import ScanResult
from scripts.mac_cleanup.paths import inspect_path
from scripts.mac_cleanup.sessions import Session
from tests.fixtures import fake_home


class CliTest(unittest.TestCase):
    def _run(self, argv: list[str], *, trusted_home: Path | None = None) -> tuple[int, str]:
        output = io.StringIO()
        with redirect_stdout(output):
            result = main(argv, trusted_home=trusted_home)
        return result, output.getvalue().strip()

    def test_commands_are_explicit(self) -> None:
        parser = build_parser()
        for command in ("scan", "plan", "approve", "apply", "verify", "report"):
            with self.subTest(command=command):
                args = [command, "--session", "/tmp/session"]
                if command == "approve":
                    args.extend(("--batch", "safe-user-caches", "--digest", "digest"))
                elif command in {"apply", "verify"}:
                    args.extend(("--batch", "safe-user-caches"))
                value = parser.parse_args(args)
                self.assertEqual(value.command, command)

    def test_entrypoint_can_be_imported_without_running_the_cli(self) -> None:
        namespace = runpy.run_path(
            str(Path(__file__).parents[1] / "scripts" / "mac_cleanup.py")
        )

        self.assertIn("run", namespace)

    def test_scan_rejects_symlinked_session_directory_without_external_writes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home = root / "home"
            (home / "Library" / "Caches").mkdir(parents=True)
            real_session = root / "real-session"
            real_session.mkdir(mode=0o700)
            mode_before = os.stat(real_session).st_mode & 0o777
            sentinel = real_session / "keep.txt"
            sentinel.write_text("keep", encoding="utf-8")
            linked_session = root / "linked-session"
            os.symlink(real_session, linked_session)

            code, _ = self._run(
                ["scan", "--session", str(linked_session)], trusted_home=home
            )

            self.assertEqual(code, 2)
            self.assertEqual(os.stat(real_session).st_mode & 0o777, mode_before)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "keep")
            self.assertFalse((real_session / "state.json").exists())

    def test_scan_rejects_symlinked_lock_without_state_write(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home = root / "home"
            (home / "Library" / "Caches").mkdir(parents=True)
            session_path = root / "session"
            session_path.mkdir(mode=0o700)
            unrelated = root / "unrelated.txt"
            unrelated.write_text("keep", encoding="utf-8")
            os.chmod(unrelated, 0o640)
            mode_before = os.stat(unrelated).st_mode & 0o777
            os.symlink(unrelated, session_path / ".session.lock")

            code, _ = self._run(
                ["scan", "--session", str(session_path)], trusted_home=home
            )

            self.assertEqual(code, 2)
            self.assertEqual(os.stat(unrelated).st_mode & 0o777, mode_before)
            self.assertEqual(unrelated.read_text(encoding="utf-8"), "keep")
            self.assertFalse((session_path / "state.json").exists())

    def test_approve_requires_exact_batch_and_digest(self) -> None:
        parser = build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["approve", "--session", "/tmp/session"])

    def test_apply_and_verify_require_an_exact_batch(self) -> None:
        parser = build_parser()
        for command in ("apply", "verify"):
            with self.subTest(command=command), self.assertRaises(SystemExit):
                parser.parse_args([command, "--session", "/tmp/session"])

    def test_apply_accepts_dry_run_but_verify_does_not(self) -> None:
        parser = build_parser()

        value = parser.parse_args([
            "apply", "--session", "/tmp/session", "--batch", "safe", "--dry-run"
        ])

        self.assertTrue(value.dry_run)
        with self.assertRaises(SystemExit):
            parser.parse_args([
                "verify", "--session", "/tmp/session", "--batch", "safe", "--dry-run"
            ])

    def test_approve_mismatch_returns_two_without_transition(self) -> None:
        target = Target(
            id="user-caches:example",
            path="/private/tmp/example",
            kind="directory",
            risk=Risk.SAFE_REGENERABLE,
            fingerprint="deep",
        )
        inventory = ScanResult(targets=(target,), executable_target_ids=(target.id,))
        policy = {
            "schema_version": 1,
            "enabled_modules": ["user-caches"],
            "preserve_target_ids": [],
            "allow_review_required": False,
            "deep_scan_threshold_bytes": 1,
        }
        manifest = build_manifest(inventory, policy)
        with tempfile.TemporaryDirectory() as directory:
            session = Session.create(Path(directory).resolve() / "session")
            session.write_manifest(manifest)

            result = main(["approve", "--session", str(session.path), "--batch", "safe-user-caches", "--digest", "wrong"])

            self.assertEqual(result, 2)
            self.assertEqual(session.status(target.id), "pending")
            self.assertEqual(session.state["events"], [])
            self.assertEqual(
                main([
                    "approve", "--session", str(session.path), "--batch", "safe-user-caches",
                    "--digest", approval_digest(manifest, "safe-user-caches"),
                ]),
                0,
            )

    def test_apply_dry_run_and_apply_operate_only_on_the_named_batch(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home = root / "home"
            cache_root = home / "Library" / "Caches"
            cache_root.mkdir(parents=True)
            targets = []
            for name in ("first", "second"):
                path = cache_root / name
                path.mkdir()
                (path / "entry.bin").write_bytes(b"cache")
                identity = inspect_path(path, (cache_root,))
                targets.append(Target(
                    id=f"user-caches:{name}",
                    path=identity.canonical,
                    kind=identity.kind,
                    risk=Risk.SAFE_REGENERABLE,
                    fingerprint=identity.fingerprint,
                    logical_bytes=identity.logical_bytes,
                ))
            inventory = ScanResult(
                targets=tuple(targets),
                executable_target_ids=tuple(target.id for target in targets),
            )
            policy = {
                "schema_version": 1,
                "enabled_modules": ["user-caches"],
                "preserve_target_ids": [],
                "allow_review_required": False,
                "deep_scan_threshold_bytes": 1,
            }
            manifest = build_manifest(inventory, policy)
            session = Session.create(root / "session")
            session.write_manifest(manifest)
            digest = approval_digest(manifest, "safe-user-caches")
            self.assertEqual(main([
                "approve", "--session", str(session.path),
                "--batch", "safe-user-caches", "--digest", digest,
            ]), 0)
            state_before = Session.load(session.path).state

            self.assertEqual(main([
                "apply", "--session", str(session.path),
                "--batch", "safe-user-caches", "--dry-run",
            ], trusted_home=home), 0)
            self.assertEqual(Session.load(session.path).state, state_before)
            self.assertTrue(all(Path(target.path).exists() for target in targets))
            self.assertFalse((session.path / "outcomes.json").exists())

            self.assertEqual(main([
                "apply", "--session", str(session.path),
                "--batch", "safe-user-caches",
            ], trusted_home=home), 0)
            resumed = Session.load(session.path)
            self.assertTrue(all(resumed.status(target.id) == "verified" for target in targets))
            self.assertTrue(all(not Path(target.path).exists() for target in targets))
            self.assertTrue((session.path / "outcomes.json").exists())
            self.assertEqual(main([
                "verify", "--session", str(session.path),
                "--batch", "safe-user-caches",
            ], trusted_home=home), 0)
            report_code, report_path = self._run([
                "report", "--session", str(session.path),
            ], trusted_home=home)
            self.assertEqual(report_code, 0)
            report = Path(report_path).read_text(encoding="utf-8")
            self.assertIn("Removed logical bytes: 10", report)
            self.assertIn("Observed `df` free-space delta:", report)

    def test_partial_removal_persists_unknown_accounting_and_reports_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home = root / "home"
            cache_root = home / "Library" / "Caches"
            target_path = cache_root / "partial"
            target_path.mkdir(parents=True)
            first = target_path / "first.bin"
            second = target_path / "second.bin"
            first.write_bytes(b"first")
            second.write_bytes(b"second")
            identity = inspect_path(target_path, (cache_root,))
            target = Target(
                id="user-caches:partial",
                path=identity.canonical,
                kind=identity.kind,
                risk=Risk.SAFE_REGENERABLE,
                fingerprint=identity.fingerprint,
                logical_bytes=identity.logical_bytes,
            )
            batch = Batch("safe-user-caches", (target,))
            session = Session.create(root / "session")
            session.write_manifest(
                Manifest(batches=(batch,), inventory_digest="a" * 64)
            )
            session.transition(target.id, "approved")

            def remove_one_then_fail(identity: object, roots: object) -> int:
                del identity, roots
                first.unlink()
                raise OSError("simulated interruption after partial deletion")

            with patch(
                "scripts.mac_cleanup.executor.remove_tree_exact",
                side_effect=remove_one_then_fail,
            ):
                apply_code, apply_text = self._run(
                    [
                        "apply",
                        "--session",
                        str(session.path),
                        "--batch",
                        batch.id,
                    ],
                    trusted_home=home,
                )

            self.assertEqual(apply_code, 3)
            summary = json.loads(apply_text)
            self.assertIsNone(summary["logical_bytes_removed"])
            self.assertEqual(summary["uncertain_target_ids"], [target.id])
            self.assertFalse(first.exists())
            self.assertTrue(second.exists())
            operation = read_json(session.path / "outcomes.json")["operations"][0]
            self.assertIsNone(operation["logical_bytes_removed"])
            self.assertEqual(operation["uncertain_target_ids"], [target.id])

            report_code, report_path = self._run(
                ["report", "--session", str(session.path)], trusted_home=home
            )

            self.assertEqual(report_code, 4)
            report = Path(report_path).read_text(encoding="utf-8")
            self.assertIn("Removed logical bytes: unknown", report)
            self.assertIn(f"Removal accounting uncertainty: `{target.id}`", report)

    def test_removed_target_with_failed_applied_checkpoint_is_durable_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home = root / "home"
            cache_root = home / "Library" / "Caches"
            target_path = cache_root / "checkpoint"
            target_path.mkdir(parents=True)
            (target_path / "entry.bin").write_bytes(b"cache")
            identity = inspect_path(target_path, (cache_root,))
            target = Target(
                id="user-caches:checkpoint",
                path=identity.canonical,
                kind=identity.kind,
                risk=Risk.SAFE_REGENERABLE,
                fingerprint=identity.fingerprint,
                logical_bytes=identity.logical_bytes,
            )
            batch = Batch("safe-user-caches", (target,))
            session = Session.create(root / "session")
            session.write_manifest(
                Manifest(batches=(batch,), inventory_digest="a" * 64)
            )
            session.transition(target.id, "approved")
            real_transition = Session.transition
            failed = False

            def fail_applied_once(
                current: Session, target_id: str, destination: str
            ) -> None:
                nonlocal failed
                if not failed and destination == "applied":
                    failed = True
                    raise OSError("simulated applied checkpoint failure")
                real_transition(current, target_id, destination)

            with patch.object(Session, "transition", new=fail_applied_once):
                apply_code, apply_text = self._run(
                    [
                        "apply",
                        "--session",
                        str(session.path),
                        "--batch",
                        batch.id,
                    ],
                    trusted_home=home,
                )

            self.assertEqual(apply_code, 4)
            summary = json.loads(apply_text)
            self.assertEqual(summary["status"], "suspended")
            self.assertIsNone(summary["logical_bytes_removed"])
            self.assertEqual(summary["uncertain_target_ids"], [target.id])
            self.assertFalse(target_path.exists())
            resumed = Session.load(session.path)
            self.assertEqual(resumed.status(target.id), "approved")
            self.assertEqual(
                resumed.critical_issue().code,  # type: ignore[union-attr]
                "executor.lifecycle-checkpoint-failed",
            )
            operation = read_json(session.path / "outcomes.json")["operations"][0]
            self.assertIsNone(operation["logical_bytes_removed"])
            self.assertEqual(operation["uncertain_target_ids"], [target.id])

            report_code, report_path = self._run(
                ["report", "--session", str(session.path)], trusted_home=home
            )

            self.assertEqual(report_code, 4)
            report = Path(report_path).read_text(encoding="utf-8")
            self.assertIn("Removed logical bytes: unknown", report)
            self.assertIn(f"Removal accounting uncertainty: `{target.id}`", report)
            self.assertIn("`executor.lifecycle-checkpoint-failed`", report)
    def test_cli_rejects_fingerprinted_user_cache_outside_trusted_home(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home = root / "home"
            (home / "Library" / "Caches").mkdir(parents=True)
            outside_root = root / "outside"
            outside_root.mkdir()
            outside = outside_root / "forged-cache"
            outside.mkdir()
            (outside / "important.bin").write_bytes(b"keep")
            identity = inspect_path(outside, (outside_root,))
            forged = Target(
                id="user-caches:forged-cache",
                path=identity.canonical,
                kind=identity.kind,
                risk=Risk.SAFE_REGENERABLE,
                fingerprint=identity.fingerprint,
                logical_bytes=identity.logical_bytes,
            )
            manifest = Manifest(
                batches=(Batch("safe-user-caches", (forged,)),),
                inventory_digest="a" * 64,
            )
            session = Session.create(root / "session")
            session.write_manifest(manifest)
            digest = approval_digest(manifest, "safe-user-caches")
            self.assertEqual(main([
                "approve", "--session", str(session.path),
                "--batch", "safe-user-caches", "--digest", digest,
            ]), 0)

            result = main([
                "apply", "--session", str(session.path),
                "--batch", "safe-user-caches",
            ], trusted_home=home)

            self.assertEqual(result, 4)
            self.assertTrue(outside.exists())
            resumed = Session.load(session.path)
            self.assertEqual(
                resumed.critical_issue().code, "executor.symlink-or-outside"
            )

    def test_scan_and_plan_write_durable_artifacts_and_deterministic_summaries(self) -> None:
        with fake_home() as home, tempfile.TemporaryDirectory() as directory:
            session_path = Path(directory).resolve() / "session"

            scan_code, scan_text = self._run(
                ["scan", "--session", str(session_path)], trusted_home=home
            )
            session = Session.load(session_path)
            policy = session.read_policy()
            policy["deep_scan_threshold_bytes"] = 1
            session.write_policy(policy)
            scan_code, scan_text = self._run(
                ["scan", "--session", str(session_path)], trusted_home=home
            )
            plan_code, plan_text = self._run(
                ["plan", "--session", str(session_path)], trusted_home=home
            )

            self.assertEqual((scan_code, plan_code), (0, 0))
            scan_summary = json.loads(scan_text)
            plan_summary = json.loads(plan_text)
            self.assertEqual(scan_summary["command"], "scan")
            self.assertTrue(session.inventory_path.exists())
            self.assertTrue(session.policy_path.exists())
            self.assertTrue(session.manifest_path.exists())
            self.assertEqual(
                [batch["id"] for batch in plan_summary["batches"]],
                ["safe-user-caches"],
            )
            self.assertRegex(plan_summary["batches"][0]["approval_digest"], r"^[0-9a-f]{64}$")

    def test_scan_reports_present_but_unavailable_cache_root(self) -> None:
        with fake_home() as home, tempfile.TemporaryDirectory() as directory:
            session_path = Path(directory).resolve() / "session"

            with patch(
                "scripts.mac_cleanup.modules.user_caches.os.access",
                return_value=False,
            ):
                code, text = self._run(
                    ["scan", "--session", str(session_path)], trusted_home=home
                )

            summary = json.loads(text)
            inventory = read_json(session_path / "inventory.json")
            self.assertEqual(code, 0)
            self.assertEqual(summary["detected_modules"], ["user-caches"])
            self.assertEqual(summary["issue_count"], 1)
            self.assertEqual(
                [issue["code"] for issue in inventory["issues"]],
                ["user-caches.cache-root-unavailable"],
            )

    def test_report_command_writes_report_and_prints_only_its_path(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            session = Session.create(Path(directory).resolve() / "session")
            session.write_manifest(Manifest(inventory_digest="a" * 64))

            code, output = self._run(["report", "--session", str(session.path)])

            self.assertEqual(code, 0)
            self.assertEqual(output, str(session.report_path))
            self.assertIn("# Mac Cleanup Report", session.report_path.read_text(encoding="utf-8"))

    def test_report_rejects_tampered_outcome_without_printing_or_writing_it(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            target = Target(
                id="user-caches:forged",
                path=str(root / "home" / "Library" / "Caches" / "forged"),
                kind="directory",
                risk=Risk.SAFE_REGENERABLE,
                fingerprint="a" * 64,
                logical_bytes=4,
            )
            session = Session.create(root / "session")
            session.write_manifest(
                Manifest(
                    batches=(Batch("safe-user-caches", (target,)),),
                    inventory_digest="b" * 64,
                )
            )
            from scripts.mac_cleanup.reporting import record_batch_outcome

            record_batch_outcome(
                session,
                "apply",
                BatchOutcome(
                    batch_id="safe-user-caches",
                    logical_bytes_removed=4,
                    logical_bytes_removed_by_target=((target.id, 4),),
                    free_space_before=10,
                    free_space_after=14,
                    issues=(
                        Issue("z.warning", Severity.WARNING, "later"),
                        Issue("a.info", Severity.INFORMATIONAL, "earlier"),
                    ),
                ),
            )
            outcomes_path = session.path / "outcomes.json"
            valid = read_json(outcomes_path)
            mutations = {
                "forged delta": lambda item: item.update(free_space_delta=4_000_000),
                "dry run with removal": lambda item: item.update(dry_run=True),
                "dry run without removal": lambda item: item.update(
                    dry_run=True,
                    logical_bytes_removed=0,
                    logical_bytes_removed_by_target=[],
                ),
                "reversed issues": lambda item: item["issues"].reverse(),
                "duplicate issue": lambda item: item["issues"].append(
                    copy.deepcopy(item["issues"][0])
                ),
            }
            session.write_report("sentinel report\n")
            for label, mutate in mutations.items():
                with self.subTest(label=label):
                    document = copy.deepcopy(valid)
                    mutate(document["operations"][0])
                    atomic_write_json(outcomes_path, document)

                    code, output = self._run(
                        ["report", "--session", str(session.path)]
                    )

                    self.assertEqual(code, 2)
                    self.assertEqual(output, "")
                    self.assertEqual(
                        session.report_path.read_text(encoding="utf-8"),
                        "sentinel report\n",
                    )

    def test_lock_replacement_before_outcome_read_latches_without_mutation(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home = root / "home"
            cache_root = home / "Library" / "Caches"
            target_path = cache_root / "pre-read"
            target_path.mkdir(parents=True)
            (target_path / "entry.bin").write_bytes(b"keep")
            identity = inspect_path(target_path, (cache_root,))
            target = Target(
                id="user-caches:pre-read",
                path=identity.canonical,
                kind=identity.kind,
                risk=Risk.SAFE_REGENERABLE,
                fingerprint=identity.fingerprint,
                logical_bytes=identity.logical_bytes,
            )
            batch = Batch("safe-user-caches", (target,))
            session = Session.create(root / "session")
            session.write_manifest(
                Manifest(batches=(batch,), inventory_digest="a" * 64)
            )
            session.transition(target.id, "approved")
            from scripts.mac_cleanup.reporting import (
                record_batch_outcome,
                validate_outcome_history as real_validate,
            )

            record_batch_outcome(
                session,
                "apply",
                BatchOutcome(batch_id=batch.id),
            )
            outcomes_path = session.path / "outcomes.json"
            outcomes_before = outcomes_path.read_bytes()
            state_before = session.state

            def replace_lock_then_validate(current: Session) -> None:
                replacement = current.path / ".replacement.lock"
                replacement.write_bytes(b"")
                os.chmod(replacement, 0o600)
                os.replace(replacement, current.lock_path)
                real_validate(current)

            with patch(
                "scripts.mac_cleanup.cli.validate_outcome_history",
                side_effect=replace_lock_then_validate,
            ):
                code, output = self._run(
                    ["apply", "--session", str(session.path), "--batch", batch.id],
                    trusted_home=home,
                )

            resumed = Session.load(session.path)
            self.assertEqual(code, 4)
            self.assertEqual(
                json.loads(output)["critical_issue"]["code"],
                "reporting.accounting-lock-lost",
            )
            self.assertTrue(target_path.exists())
            self.assertEqual(resumed.status(target.id), "approved")
            self.assertEqual(resumed.state["events"], state_before["events"])
            self.assertEqual(outcomes_path.read_bytes(), outcomes_before)
            self.assertEqual(
                resumed.critical_issue().code,
                "reporting.accounting-lock-lost",
            )

    def test_lock_replacement_after_apply_latches_and_never_trusts_forged_outcomes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home = root / "home"
            cache_root = home / "Library" / "Caches"
            cache_root.mkdir(parents=True)
            targets: list[Target] = []
            for name, risk in (
                ("removed", Risk.SAFE_REGENERABLE),
                ("future", Risk.REVIEW_REQUIRED),
            ):
                path = cache_root / name
                path.mkdir()
                (path / "entry.bin").write_bytes(b"cache")
                identity = inspect_path(path, (cache_root,))
                targets.append(
                    Target(
                        id=f"user-caches:{name}",
                        path=identity.canonical,
                        kind=identity.kind,
                        risk=risk,
                        fingerprint=identity.fingerprint,
                        logical_bytes=identity.logical_bytes,
                    )
                )
            safe_batch = Batch("safe-user-caches", (targets[0],))
            future_batch = Batch("review-user-caches", (targets[1],))
            session = Session.create(root / "session")
            session.write_manifest(
                Manifest(
                    batches=(safe_batch, future_batch),
                    inventory_digest="a" * 64,
                )
            )
            for target in targets:
                session.transition(target.id, "approved")
            outcomes_path = session.path / "outcomes.json"
            forged = b'{"operations":[{"forged":true}],"schema_version":1}'
            replaced = False

            def publish_then_replace(path: str | Path, value: object) -> None:
                nonlocal replaced
                atomic_write_json(path, value)
                if Path(path) == outcomes_path and not replaced:
                    replaced = True
                    replacement = session.path / ".replacement.lock"
                    replacement.write_bytes(b"")
                    os.chmod(replacement, 0o600)
                    os.replace(replacement, session.lock_path)
                    outcomes_path.write_bytes(forged)
                    os.chmod(outcomes_path, 0o600)

            with patch(
                "scripts.mac_cleanup.reporting.atomic_write_json",
                side_effect=publish_then_replace,
            ):
                code, output = self._run(
                    [
                        "apply",
                        "--session",
                        str(session.path),
                        "--batch",
                        safe_batch.id,
                    ],
                    trusted_home=home,
                )

            resumed = Session.load(session.path)
            self.assertTrue(replaced)
            self.assertEqual(code, 4)
            self.assertEqual(
                json.loads(output)["critical_issue"]["code"],
                "reporting.accounting-lock-lost",
            )
            self.assertFalse(Path(targets[0].path).exists())
            self.assertEqual(resumed.status(targets[0].id), "verified")
            self.assertEqual(resumed.status(targets[1].id), "approved")
            self.assertEqual(outcomes_path.read_bytes(), forged)
            self.assertEqual(
                resumed.critical_issue().code,
                "reporting.accounting-lock-lost",
            )

            for command in ("apply", "verify"):
                future_code, _ = self._run(
                    [
                        command,
                        "--session",
                        str(session.path),
                        "--batch",
                        future_batch.id,
                    ],
                    trusted_home=home,
                )
                self.assertEqual(future_code, 4)
                self.assertTrue(Path(targets[1].path).exists())
                self.assertEqual(
                    Session.load(session.path).status(targets[1].id),
                    "approved",
                )

            report_code, report_path = self._run(
                ["report", "--session", str(session.path)], trusted_home=home
            )
            self.assertEqual(report_code, 4)
            report = Path(report_path).read_text(encoding="utf-8")
            self.assertIn("reporting.accounting-lock-lost", report)
            self.assertIn("Removed logical bytes: unknown", report)
            self.assertNotIn("forged", report)
            self.assertEqual(outcomes_path.read_bytes(), forged)

    def test_apply_and_verify_reject_existing_forged_outcomes_before_mutation(self) -> None:
        for command, dry_run in (("apply", False), ("apply", True), ("verify", False)):
            with self.subTest(command=command, dry_run=dry_run), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                home = root / "home"
                cache_root = home / "Library" / "Caches"
                target_path = cache_root / "blocked"
                target_path.mkdir(parents=True)
                (target_path / "entry.bin").write_bytes(b"keep")
                identity = inspect_path(target_path, (cache_root,))
                target = Target(
                    id="user-caches:blocked",
                    path=identity.canonical,
                    kind=identity.kind,
                    risk=Risk.SAFE_REGENERABLE,
                    fingerprint=identity.fingerprint,
                    logical_bytes=identity.logical_bytes,
                )
                batch = Batch("safe-user-caches", (target,))
                session = Session.create(root / "session")
                session.write_manifest(
                    Manifest(batches=(batch,), inventory_digest="a" * 64)
                )
                session.transition(target.id, "approved")
                if command == "verify":
                    session.transition(target.id, "applied")
                from scripts.mac_cleanup.reporting import record_batch_outcome

                record_batch_outcome(
                    session,
                    "apply",
                    BatchOutcome(
                        batch_id=batch.id,
                        free_space_before=100,
                        free_space_after=105,
                    ),
                )
                outcomes_path = session.path / "outcomes.json"
                forged = read_json(outcomes_path)
                forged["operations"][0]["free_space_delta"] = 999
                atomic_write_json(outcomes_path, forged)
                state_before = Session.load(session.path).state
                outcomes_before = outcomes_path.read_bytes()

                arguments = [
                    command,
                    "--session",
                    str(session.path),
                    "--batch",
                    batch.id,
                ]
                if dry_run:
                    arguments.append("--dry-run")
                code, output = self._run(arguments, trusted_home=home)

                self.assertEqual(code, 2)
                self.assertEqual(output, "")
                self.assertTrue(target_path.exists())
                self.assertEqual(Session.load(session.path).state, state_before)
                self.assertEqual(outcomes_path.read_bytes(), outcomes_before)

    def test_apply_orders_concurrent_outcome_replacement_before_preflight(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home = root / "home"
            cache_root = home / "Library" / "Caches"
            target_path = cache_root / "ordered"
            target_path.mkdir(parents=True)
            (target_path / "entry.bin").write_bytes(b"keep")
            identity = inspect_path(target_path, (cache_root,))
            target = Target(
                id="user-caches:ordered",
                path=identity.canonical,
                kind=identity.kind,
                risk=Risk.SAFE_REGENERABLE,
                fingerprint=identity.fingerprint,
                logical_bytes=identity.logical_bytes,
            )
            batch = Batch("safe-user-caches", (target,))
            session = Session.create(root / "session")
            session.write_manifest(
                Manifest(batches=(batch,), inventory_digest="a" * 64)
            )
            session.transition(target.id, "approved")
            from scripts.mac_cleanup.reporting import record_batch_outcome

            record_batch_outcome(
                session,
                "apply",
                BatchOutcome(
                    batch_id=batch.id,
                    free_space_before=100,
                    free_space_after=105,
                ),
            )
            outcomes_path = session.path / "outcomes.json"
            forged = read_json(outcomes_path)
            forged["operations"][0]["free_space_delta"] = 999
            replacement_written = threading.Event()
            release_replacer = threading.Event()
            apply_started = threading.Event()
            apply_done = threading.Event()
            result: dict[str, int] = {}

            def replace_while_locked() -> None:
                replacing = Session.load(session.path)
                with replacing.operation_lock():
                    atomic_write_json(outcomes_path, forged)
                    replacement_written.set()
                    if not release_replacer.wait(5):
                        raise AssertionError("test did not release outcome replacer")

            def apply_operation() -> None:
                apply_started.set()
                result["code"] = main(
                    ["apply", "--session", str(session.path), "--batch", batch.id],
                    trusted_home=home,
                )
                apply_done.set()

            replacing_thread = threading.Thread(target=replace_while_locked)
            replacing_thread.start()
            self.assertTrue(replacement_written.wait(5))
            with patch("scripts.mac_cleanup.cli._print_json"):
                applying_thread = threading.Thread(target=apply_operation)
                applying_thread.start()
                self.assertTrue(apply_started.wait(5))
                self.assertFalse(apply_done.wait(0.1))
                release_replacer.set()
                replacing_thread.join(5)
                applying_thread.join(5)

            self.assertFalse(replacing_thread.is_alive())
            self.assertFalse(applying_thread.is_alive())
            self.assertEqual(result, {"code": 2})
            self.assertTrue(target_path.exists())
            self.assertEqual(Session.load(session.path).status(target.id), "approved")

    def test_apply_holds_one_lock_from_preflight_through_outcome_recording(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home = root / "home"
            cache_root = home / "Library" / "Caches"
            target_path = cache_root / "coherent-apply"
            target_path.mkdir(parents=True)
            (target_path / "entry.bin").write_bytes(b"delete")
            identity = inspect_path(target_path, (cache_root,))
            target = Target(
                id="user-caches:coherent-apply",
                path=identity.canonical,
                kind=identity.kind,
                risk=Risk.SAFE_REGENERABLE,
                fingerprint=identity.fingerprint,
                logical_bytes=identity.logical_bytes,
            )
            batch = Batch("safe-user-caches", (target,))
            session = Session.create(root / "session")
            session.write_manifest(
                Manifest(batches=(batch,), inventory_digest="a" * 64)
            )
            session.transition(target.id, "approved")
            mutation_finished = threading.Event()
            replacement_attempted = threading.Event()
            replacement_done = threading.Event()
            results: dict[str, int] = {}

            def observed_apply(*args: object, **kwargs: object) -> BatchOutcome:
                outcome = engine_apply_batch(*args, **kwargs)
                if not kwargs.get("dry_run", False):
                    mutation_finished.set()
                    if not replacement_attempted.wait(5):
                        raise AssertionError("replacement thread did not attempt the lock")
                    if replacement_done.wait(0.1):
                        raise AssertionError("outcome replacement entered the transaction")
                return outcome

            def replace_outcomes() -> None:
                if not mutation_finished.wait(5):
                    raise AssertionError("apply did not reach its mutation checkpoint")
                replacement_attempted.set()
                replacing = Session.load(session.path)
                with replacing.operation_lock():
                    atomic_write_json(
                        session.path / "outcomes.json",
                        {
                            "schema_version": 1,
                            "operations": [{"forged": True}],
                        },
                    )
                replacement_done.set()

            def apply_operation() -> None:
                results["code"] = main(
                    ["apply", "--session", str(session.path), "--batch", batch.id],
                    trusted_home=home,
                )

            replacement_thread = threading.Thread(target=replace_outcomes)
            replacement_thread.start()
            with patch("scripts.mac_cleanup.cli.apply_batch", side_effect=observed_apply), patch(
                "scripts.mac_cleanup.cli._print_json"
            ):
                applying_thread = threading.Thread(target=apply_operation)
                applying_thread.start()
                applying_thread.join(5)
            replacement_thread.join(5)

            self.assertFalse(applying_thread.is_alive())
            self.assertFalse(replacement_thread.is_alive())
            self.assertEqual(results, {"code": 0})
            self.assertTrue(replacement_done.is_set())
            self.assertFalse(target_path.exists())
            self.assertEqual(Session.load(session.path).status(target.id), "verified")

    def test_report_returns_four_for_tampered_bound_artifact_after_verified(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home = root / "home"
            cache_root = home / "Library" / "Caches"
            target_path = cache_root / "admin"
            target_path.mkdir(parents=True)
            (target_path / "entry.bin").write_bytes(b"cache")
            identity = inspect_path(target_path, (cache_root,))
            target = Target(
                id="user-caches:admin",
                path=identity.canonical,
                kind=identity.kind,
                risk=Risk.SAFE_REGENERABLE,
                fingerprint=identity.fingerprint,
                logical_bytes=identity.logical_bytes,
            )
            batch = Batch("safe-user-caches", (target,))
            session = Session.create(root / "session")
            session.write_manifest(
                Manifest(batches=(batch,), inventory_digest="a" * 64)
            )
            session.transition(target.id, "approved")
            from scripts.mac_cleanup.admin_script import generate_admin_script

            script_path = session.path / "admin.zsh"
            generate_admin_script(
                batch,
                script_path,
                session.path / "admin-result.json",
                trusted_home=home,
            )
            session.transition(target.id, "applied")
            session.transition(target.id, "verified")
            state_before = session.state
            script_path.write_text("#!/bin/zsh\nexit 0\n", encoding="utf-8")

            code, output = self._run(
                ["report", "--session", str(session.path)], trusted_home=home
            )

            self.assertEqual(code, 4)
            self.assertEqual(output, "")
            self.assertFalse(session.report_path.exists())
            self.assertEqual(Session.load(session.path).state, state_before)

    def test_plan_strictly_rejects_malformed_inventory_without_state_or_manifest_write(self) -> None:
        valid_target = {
            "id": "user-caches:valid",
            "path": "/private/tmp/valid",
            "kind": "directory",
            "risk": "safe_regenerable",
            "status": "pending",
            "fingerprint": "a" * 64,
            "logical_bytes": 1,
        }
        valid = {
            "capabilities": {
                "modules": [{"detected": True, "id": "user-caches"}],
                "tools": [{"available": True, "name": "python3"}],
            },
            "executable_target_ids": ["user-caches:valid"],
            "issues": [
                {"code": "scan.note", "severity": "informational", "message": "ok"}
            ],
            "schema_version": 1,
            "targets": [valid_target],
        }

        def mutate_unknown_capability(value: dict[str, object]) -> None:
            value["capabilities"]["unknown"] = []

        def mutate_missing_target_field(value: dict[str, object]) -> None:
            del value["targets"][0]["status"]

        def mutate_negative_bytes(value: dict[str, object]) -> None:
            value["targets"][0]["logical_bytes"] = -1

        def mutate_duplicate_target(value: dict[str, object]) -> None:
            value["targets"].append(copy.deepcopy(value["targets"][0]))

        def mutate_invalid_enum(value: dict[str, object]) -> None:
            value["targets"][0]["risk"] = "unsafe"

        def mutate_nonpending(value: dict[str, object]) -> None:
            value["targets"][0]["status"] = "approved"

        def mutate_bad_digest(value: dict[str, object]) -> None:
            value["targets"][0]["fingerprint"] = "deep"

        def mutate_shallow_executable(value: dict[str, object]) -> None:
            value["targets"][0]["fingerprint"] = ""

        def mutate_issue_extra(value: dict[str, object]) -> None:
            value["issues"][0]["extra"] = True

        def mutate_tool_type(value: dict[str, object]) -> None:
            value["capabilities"]["tools"][0]["available"] = 1

        def mutate_boolean_schema(value: dict[str, object]) -> None:
            value["schema_version"] = True

        mutations = (
            mutate_unknown_capability,
            mutate_missing_target_field,
            mutate_negative_bytes,
            mutate_duplicate_target,
            mutate_invalid_enum,
            mutate_nonpending,
            mutate_bad_digest,
            mutate_shallow_executable,
            mutate_issue_extra,
            mutate_tool_type,
            mutate_boolean_schema,
        )
        for mutate in mutations:
            with self.subTest(mutation=mutate.__name__), tempfile.TemporaryDirectory() as directory:
                root = Path(directory).resolve()
                session = Session.create(root / "session")
                session.write_policy(
                    {
                        "schema_version": 1,
                        "enabled_modules": ["user-caches"],
                        "preserve_target_ids": [],
                        "allow_review_required": False,
                        "deep_scan_threshold_bytes": 1,
                    }
                )
                inventory = copy.deepcopy(valid)
                mutate(inventory)
                session.write_inventory(inventory)
                state_before = session.state

                code, output = self._run(["plan", "--session", str(session.path)])

                self.assertEqual(code, 2)
                self.assertEqual(output, "")
                self.assertEqual(Session.load(session.path).state, state_before)
                self.assertFalse(session.manifest_path.exists())

    def test_plan_rejects_noncanonical_raw_path_spellings_without_writes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            fixture_root = Path(directory).resolve()
            real = fixture_root / "real"
            real.mkdir()
            alias = fixture_root / "alias"
            alias.symlink_to(real, target_is_directory=True)
            canonical = real / "valid"
            raw_paths = {
                "trailing slash": f"{canonical}/",
                "dot segment": f"{real}/./valid",
                "duplicate separator": f"{fixture_root}//real/valid",
                "symlink alias": f"{alias}/valid",
                "relative": "real/valid",
            }
            for label, raw_path in raw_paths.items():
                with self.subTest(label=label), tempfile.TemporaryDirectory() as session_dir:
                    session = Session.create(Path(session_dir).resolve() / "session")
                    session.write_policy(
                        {
                            "schema_version": 1,
                            "enabled_modules": ["user-caches"],
                            "preserve_target_ids": [],
                            "allow_review_required": False,
                            "deep_scan_threshold_bytes": 1,
                        }
                    )
                    session.write_inventory(
                        {
                            "capabilities": {
                                "modules": [{"detected": True, "id": "user-caches"}],
                                "tools": [{"available": True, "name": "python3"}],
                            },
                            "executable_target_ids": ["user-caches:valid"],
                            "issues": [],
                            "schema_version": 1,
                            "targets": [
                                {
                                    "id": "user-caches:valid",
                                    "path": raw_path,
                                    "kind": "directory",
                                    "risk": "safe_regenerable",
                                    "status": "pending",
                                    "fingerprint": "a" * 64,
                                    "logical_bytes": 1,
                                }
                            ],
                        }
                    )
                    state_before = session.state

                    code, output = self._run(
                        ["plan", "--session", str(session.path)]
                    )

                    self.assertEqual(code, 2)
                    self.assertEqual(output, "")
                    self.assertEqual(Session.load(session.path).state, state_before)
                    self.assertFalse(session.manifest_path.exists())

    def test_scan_and_plan_are_serialized_and_plan_binds_complete_inventory(self) -> None:
        with fake_home() as home, tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            session = Session.create(root / "session")
            session.write_policy(
                {
                    "schema_version": 1,
                    "enabled_modules": ["user-caches"],
                    "preserve_target_ids": [],
                    "allow_review_required": False,
                    "deep_scan_threshold_bytes": 1,
                }
            )
            entered = threading.Event()
            release = threading.Event()
            plan_started = threading.Event()
            plan_done = threading.Event()
            target = Target(
                id="user-caches:coherent",
                path=str(home / "Library" / "Caches" / "coherent"),
                kind="directory",
                risk=Risk.SAFE_REGENERABLE,
                fingerprint="a" * 64,
                logical_bytes=7,
            )

            class BlockingModule:
                id = "user-caches"

                def detect(self, context: object) -> bool:
                    return True

                def fast_scan(self, context: object) -> ScanResult:
                    entered.set()
                    self.assert_release()
                    return ScanResult(
                        targets=(
                            Target(
                                id=target.id,
                                path=target.path,
                                kind=target.kind,
                                risk=target.risk,
                            ),
                        )
                    )

                def assert_release(self) -> None:
                    if not release.wait(5):
                        raise AssertionError("test did not release scan")

                def deep_scan(self, context: object, candidate_ids: tuple[str, ...]) -> ScanResult:
                    return ScanResult(targets=(target,), executable_target_ids=(target.id,))

            results: dict[str, int] = {}

            def scan_operation() -> None:
                results["scan"] = _scan(session.path, home)

            def plan_operation() -> None:
                plan_started.set()
                results["plan"] = _plan(session.path)
                plan_done.set()

            with patch(
                "scripts.mac_cleanup.cli.registered_modules",
                return_value=(BlockingModule(),),
            ), patch("scripts.mac_cleanup.cli._print_json"):
                scan_thread = threading.Thread(target=scan_operation)
                scan_thread.start()
                self.assertTrue(entered.wait(5))
                plan_thread = threading.Thread(target=plan_operation)
                plan_thread.start()
                self.assertTrue(plan_started.wait(5))
                self.assertFalse(plan_done.wait(0.1))
                release.set()
                scan_thread.join(5)
                plan_thread.join(5)

            self.assertFalse(scan_thread.is_alive())
            self.assertFalse(plan_thread.is_alive())
            self.assertEqual(results, {"scan": 0, "plan": 0})
            resumed = Session.load(session.path)
            expected = build_manifest(
                _scan_result(resumed.read_inventory()), resumed.read_policy()
            )
            self.assertEqual(resumed.read_manifest(), expected)

    def test_changed_batch_returns_three_and_invalid_input_returns_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home = root / "home"
            cache_root = home / "Library" / "Caches"
            target_path = cache_root / "changed"
            target_path.mkdir(parents=True)
            (target_path / "entry.bin").write_bytes(b"old")
            identity = inspect_path(target_path, (cache_root,))
            target = Target(
                id="user-caches:changed",
                path=identity.canonical,
                kind=identity.kind,
                risk=Risk.SAFE_REGENERABLE,
                fingerprint=identity.fingerprint,
                logical_bytes=identity.logical_bytes,
            )
            manifest = Manifest(
                batches=(Batch("safe-user-caches", (target,)),),
                inventory_digest="a" * 64,
            )
            session = Session.create(root / "session")
            session.write_manifest(manifest)
            session.transition(target.id, "approved")
            (target_path / "entry.bin").write_bytes(b"new content")

            suspended, _ = self._run(
                ["apply", "--session", str(session.path), "--batch", "safe-user-caches"],
                trusted_home=home,
            )
            invalid, _ = self._run(["report", "--session", str(root / "missing")])

            self.assertEqual(suspended, 3)
            self.assertEqual(invalid, 2)

    def test_permission_fallback_surfaces_checksum_and_exact_script_precondition(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home = root / "home"
            cache_root = home / "Library" / "Caches"
            target_path = cache_root / "protected"
            target_path.mkdir(parents=True)
            (target_path / "entry.bin").write_bytes(b"cache")
            identity = inspect_path(target_path, (cache_root,))
            target = Target(
                id="user-caches:protected",
                path=identity.canonical,
                kind=identity.kind,
                risk=Risk.SAFE_REGENERABLE,
                fingerprint=identity.fingerprint,
                logical_bytes=identity.logical_bytes,
            )
            batch = Batch("safe-user-caches", (target,))
            session = Session.create(root / "session")
            session.write_manifest(
                Manifest(batches=(batch,), inventory_digest="a" * 64)
            )
            session.transition(target.id, "approved")
            permission = BatchOutcome(
                batch_id=batch.id,
                issues=(
                    Issue(
                        "executor.permission-denied",
                        Severity.BATCH_ERROR,
                        "permission denied",
                        target.id,
                    ),
                ),
                dry_run=True,
                suspended=True,
            )

            with patch("scripts.mac_cleanup.cli.apply_batch", return_value=permission):
                code, text = self._run(
                    ["apply", "--session", str(session.path), "--batch", batch.id],
                    trusted_home=home,
                )

            value = json.loads(text)
            self.assertEqual(code, 3)
            self.assertRegex(value["checksum"], r"^[0-9a-f]{64}$")
            self.assertIn("Execute exactly the engine-validated script path", value["manual_precondition"])
            self.assertIn("does not close", value["manual_precondition"])
            self.assertTrue(Path(value["script_path"]).is_file())

            Path(value["script_path"]).write_text("#!/bin/zsh\nexit 0\n", encoding="utf-8")
            verify_code, verify_text = self._run(
                ["verify", "--session", str(session.path), "--batch", batch.id],
                trusted_home=home,
            )
            self.assertEqual(verify_code, 4)
            self.assertEqual(
                json.loads(verify_text)["critical_issue"],
                "administrative artifact validation failed",
            )
            self.assertTrue(target_path.exists())

    def test_cli_verify_is_matching_admin_intent_accounting_resolver(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home = root / "home"
            cache_root = home / "Library" / "Caches"
            target_path = cache_root / "admin-resolve"
            target_path.mkdir(parents=True)
            (target_path / "entry.bin").write_bytes(b"cache")
            identity = inspect_path(target_path, (cache_root,))
            target = Target(
                id="user-caches:admin-resolve",
                path=identity.canonical,
                kind=identity.kind,
                risk=Risk.SAFE_REGENERABLE,
                fingerprint=identity.fingerprint,
                logical_bytes=identity.logical_bytes,
            )
            batch = Batch("safe-user-caches", (target,))
            session = Session.create(root / "session")
            session.write_manifest(
                Manifest(batches=(batch,), inventory_digest="a" * 64)
            )
            session.transition(target.id, "approved")
            from scripts.mac_cleanup.admin_script import generate_admin_script

            script_path = session.path / "admin.zsh"
            generate_admin_script(
                batch,
                script_path,
                session.path / "admin-result.json",
                trusted_home=home,
            )
            completed = subprocess.run(
                (str(script_path),), capture_output=True, text=True, check=False
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIsNotNone(Session.load(session.path).mutation_intent())

            code, output = self._run(
                [
                    "verify",
                    "--session",
                    str(session.path),
                    "--batch",
                    batch.id,
                ],
                trusted_home=home,
            )

            self.assertEqual(code, 0, output)
            resolved = Session.load(session.path)
            self.assertIsNone(resolved.mutation_intent())
            self.assertEqual(resolved.status(target.id), "verified")
            operations = read_json(session.path / "outcomes.json")["operations"]
            self.assertEqual(
                [operation["operation"] for operation in operations],
                ["apply", "verify"],
            )

    def test_outcome_write_failure_after_delete_leaves_durable_stop(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home = root / "home"
            cache_root = home / "Library" / "Caches"
            target_path = cache_root / "publication"
            target_path.mkdir(parents=True)
            (target_path / "entry.bin").write_bytes(b"cache")
            identity = inspect_path(target_path, (cache_root,))
            target = Target(
                id="user-caches:publication",
                path=identity.canonical,
                kind=identity.kind,
                risk=Risk.SAFE_REGENERABLE,
                fingerprint=identity.fingerprint,
                logical_bytes=identity.logical_bytes,
            )
            batch = Batch("safe-user-caches", (target,))
            session = Session.create(root / "session")
            session.write_manifest(
                Manifest(batches=(batch,), inventory_digest="a" * 64)
            )
            session.transition(target.id, "approved")
            real_write = atomic_write_json

            def fail_outcome(path: str | Path, value: object) -> None:
                if Path(path).name == "outcomes.json":
                    raise OSError("simulated outcome publication failure")
                real_write(path, value)

            with patch(
                "scripts.mac_cleanup.reporting.atomic_write_json",
                side_effect=fail_outcome,
            ):
                code, text = self._run(
                    ["apply", "--session", str(session.path), "--batch", batch.id],
                    trusted_home=home,
                )

            self.assertEqual(code, 4)
            self.assertFalse(target_path.exists())
            self.assertIsNotNone(Session.load(session.path).mutation_intent())
            self.assertFalse((session.path / "outcomes.json").exists())
            self.assertIn(
                "executor.outcome-publication-failed",
                {issue["code"] for issue in json.loads(text)["issues"]},
            )

            with patch(
                "scripts.mac_cleanup.executor.remove_tree_exact"
            ) as retried:
                for command in ("apply", "verify"):
                    retry_code, retry_text = self._run(
                        [
                            command,
                            "--session",
                            str(session.path),
                            "--batch",
                            batch.id,
                        ],
                        trusted_home=home,
                    )
                    self.assertEqual(retry_code, 4)
                    self.assertIn("unresolved-mutation-intent", retry_text)
            retried.assert_not_called()

    def test_applied_and_latch_failures_still_block_reload_and_report(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home = root / "home"
            cache_root = home / "Library" / "Caches"
            target_path = cache_root / "double-failure"
            target_path.mkdir(parents=True)
            (target_path / "entry.bin").write_bytes(b"cache")
            identity = inspect_path(target_path, (cache_root,))
            target = Target(
                id="user-caches:double-failure",
                path=identity.canonical,
                kind=identity.kind,
                risk=Risk.SAFE_REGENERABLE,
                fingerprint=identity.fingerprint,
                logical_bytes=identity.logical_bytes,
            )
            batch = Batch("safe-user-caches", (target,))
            session = Session.create(root / "session")
            session.write_manifest(
                Manifest(batches=(batch,), inventory_digest="a" * 64)
            )
            session.transition(target.id, "approved")
            real_transition = Session.transition

            def fail_applied(
                current: Session, target_id: str, destination: str
            ) -> None:
                if destination == "applied":
                    raise OSError("simulated lifecycle failure")
                real_transition(current, target_id, destination)

            with patch.object(Session, "transition", new=fail_applied), patch.object(
                Session,
                "latch_critical",
                side_effect=OSError("simulated latch failure"),
            ):
                code, _ = self._run(
                    ["apply", "--session", str(session.path), "--batch", batch.id],
                    trusted_home=home,
                )

            resumed = Session.load(session.path)
            self.assertEqual(code, 4)
            self.assertEqual(resumed.status(target.id), "approved")
            self.assertIsNone(resumed.critical_issue())
            self.assertIsNotNone(resumed.mutation_intent())
            report_code, report_path = self._run(
                ["report", "--session", str(session.path)], trusted_home=home
            )
            self.assertEqual(report_code, 4)
            report = Path(report_path).read_text(encoding="utf-8")
            self.assertIn("Removed logical bytes: unknown", report)
            self.assertIn("Start a fresh session", report)
