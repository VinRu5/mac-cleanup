import tempfile
import unittest
from pathlib import Path

from scripts.mac_cleanup.cli import build_parser, main
from scripts.mac_cleanup.manifests import approval_digest, build_manifest
from scripts.mac_cleanup.models import Batch, Manifest, Risk, Target
from scripts.mac_cleanup.modules.base import ScanResult
from scripts.mac_cleanup.paths import inspect_path
from scripts.mac_cleanup.sessions import Session


class CliTest(unittest.TestCase):
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
            session = Session.create(Path(directory) / "session")
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

            self.assertEqual(main([
                "apply", "--session", str(session.path),
                "--batch", "safe-user-caches",
            ], trusted_home=home), 0)
            resumed = Session.load(session.path)
            self.assertTrue(all(resumed.status(target.id) == "verified" for target in targets))
            self.assertTrue(all(not Path(target.path).exists() for target in targets))

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

            self.assertEqual(result, 2)
            self.assertTrue(outside.exists())
            resumed = Session.load(session.path)
            self.assertEqual(
                resumed.critical_issue().code, "executor.symlink-or-outside"
            )
