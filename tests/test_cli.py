import tempfile
import unittest
from pathlib import Path

from scripts.mac_cleanup.cli import build_parser, main
from scripts.mac_cleanup.manifests import approval_digest, build_manifest
from scripts.mac_cleanup.models import Risk, Target
from scripts.mac_cleanup.modules.base import ScanResult
from scripts.mac_cleanup.sessions import Session


class CliTest(unittest.TestCase):
    def test_commands_are_explicit(self) -> None:
        parser = build_parser()
        for command in ("scan", "plan", "approve", "apply", "verify", "report"):
            with self.subTest(command=command):
                args = [command, "--session", "/tmp/session"]
                if command == "approve":
                    args.extend(("--batch", "safe-user-caches", "--digest", "digest"))
                value = parser.parse_args(args)
                self.assertEqual(value.command, command)

    def test_approve_requires_exact_batch_and_digest(self) -> None:
        parser = build_parser()
        with self.assertRaises(SystemExit):
            parser.parse_args(["approve", "--session", "/tmp/session"])

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
