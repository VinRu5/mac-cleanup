from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from scripts.mac_cleanup.cli import main
from scripts.mac_cleanup.jsonio import read_json
from scripts.mac_cleanup.manifests import approval_digest
from scripts.mac_cleanup.sessions import Session


class IntegrationWorkflowTest(unittest.TestCase):
    maxDiff = None

    def test_installation_handoff_documents_a_minimal_allowlist(self) -> None:
        instructions = (Path(__file__).parents[1] / "SKILL.md").read_text(
            encoding="utf-8"
        )
        normalized = " ".join(instructions.split())

        for allowed in ("`SKILL.md`", "`agents/`", "`references/`", "`scripts/`"):
            self.assertIn(allowed, normalized)
        for excluded in (
            "`.git/`",
            "`.superpowers/`",
            "task reports",
            "`__pycache__/`",
            "session directories",
        ):
            self.assertIn(excluded, normalized)
        self.assertIn("Tests are optional", normalized)

    def test_complete_fixture_workflow_is_exact_resumable_and_deterministic(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            home = root / "home"
            session_path = root / "session"
            approved = home / "Library" / "Caches" / "com.example.app"
            preserved = home / "Library" / "Caches" / "preserved.app"
            codex = home / "Library" / "Caches" / "Codex"
            sentry = home / "Library" / "Caches" / "io.sentry"
            application_support = (
                home
                / "Library"
                / "Application Support"
                / "com.example.app"
                / "config.json"
            )
            environment = home / ".env"
            project = home / "project" / "pubspec.yaml"
            self._write(approved / "cache.bin", b"cache")
            self._write(preserved / "cache.bin", b"preserve")
            self._write(codex / "session.bin", b"session")
            self._write(sentry / "event.bin", b"event")
            self._write(application_support, b"{}")
            self._write(environment, b"TOKEN=secret\n")
            self._write(project, b"name: protected\n")

            session = Session.create(session_path)
            session.write_policy(
                {
                    "schema_version": 1,
                    "enabled_modules": ["user-caches"],
                    "preserve_target_ids": ["user-caches:preserved.app"],
                    "allow_review_required": False,
                    "deep_scan_threshold_bytes": 0,
                }
            )

            scan_code, scan_text = self._run(
                ["scan", "--session", str(session_path)], trusted_home=home
            )
            plan_code, plan_text = self._run(
                ["plan", "--session", str(session_path)], trusted_home=home
            )

            self.assertEqual((scan_code, plan_code), (0, 0))
            scan = json.loads(scan_text)
            plan = json.loads(plan_text)
            self.assertEqual(scan["detected_modules"], ["user-caches"])
            self.assertEqual(
                scan["executable_target_ids"],
                [
                    "user-caches:Codex",
                    "user-caches:com.example.app",
                    "user-caches:io.sentry",
                    "user-caches:preserved.app",
                ],
            )
            self.assertEqual(
                plan["batches"],
                [
                    {
                        "approval_digest": plan["batches"][0]["approval_digest"],
                        "estimated_logical_bytes": 5,
                        "id": "safe-user-caches",
                        "target_ids": ["user-caches:com.example.app"],
                    }
                ],
            )
            digest = plan["batches"][0]["approval_digest"]
            self.assertRegex(digest, re.compile(r"^[0-9a-f]{64}$"))
            self.assertEqual(
                digest,
                approval_digest(
                    Session.load(session_path).read_manifest(), "safe-user-caches"
                ),
            )

            approve_code, _ = self._run(
                [
                    "approve",
                    "--session",
                    str(session_path),
                    "--batch",
                    "safe-user-caches",
                    "--digest",
                    digest,
                ],
                trusted_home=home,
            )
            self.assertEqual(approve_code, 0)
            home_before_dry_run = self._snapshot(home)
            state_before_dry_run = Session.load(session_path).state

            dry_run_code, dry_run_text = self._run(
                [
                    "apply",
                    "--session",
                    str(session_path),
                    "--batch",
                    "safe-user-caches",
                    "--dry-run",
                ],
                trusted_home=home,
            )

            self.assertEqual(dry_run_code, 0)
            self.assertTrue(json.loads(dry_run_text)["dry_run"])
            self.assertEqual(self._snapshot(home), home_before_dry_run)
            self.assertEqual(Session.load(session_path).state, state_before_dry_run)
            self.assertFalse((session_path / "outcomes.json").exists())

            with patch("scripts.mac_cleanup.executor._free_space", return_value=1_000):
                apply_code, apply_text = self._run(
                    [
                        "apply",
                        "--session",
                        str(session_path),
                        "--batch",
                        "safe-user-caches",
                    ],
                    trusted_home=home,
                )
                verify_code, _ = self._run(
                    [
                        "verify",
                        "--session",
                        str(session_path),
                        "--batch",
                        "safe-user-caches",
                    ],
                    trusted_home=home,
                )

            self.assertEqual((apply_code, verify_code), (0, 0))
            self.assertEqual(json.loads(apply_text)["logical_bytes_removed"], 5)
            self.assertFalse(approved.exists())
            for protected in (
                preserved,
                codex,
                sentry,
                application_support,
                environment,
                project,
            ):
                self.assertTrue(protected.exists(), protected)
            resumed = Session.load(session_path)
            self.assertEqual(resumed.status("user-caches:com.example.app"), "verified")
            state_before_resume = resumed.state

            with patch("scripts.mac_cleanup.executor._free_space", return_value=1_000):
                resumed_apply_code, resumed_apply_text = self._run(
                    [
                        "apply",
                        "--session",
                        str(session_path),
                        "--batch",
                        "safe-user-caches",
                    ],
                    trusted_home=home,
                )

            self.assertEqual(resumed_apply_code, 0)
            self.assertEqual(
                json.loads(resumed_apply_text)["logical_bytes_removed"], 0
            )
            self.assertEqual(Session.load(session_path).state, state_before_resume)
            self.assertFalse(approved.exists())
            operations = read_json(session_path / "outcomes.json")["operations"]
            self.assertEqual(
                [(item["operation"], item["logical_bytes_removed"]) for item in operations],
                [("apply", 5), ("verify", 0), ("apply", 0)],
            )

            report_code, report_path_text = self._run(
                ["report", "--session", str(session_path)], trusted_home=home
            )
            self.assertEqual(report_code, 0)
            report_path = Path(report_path_text)
            report = report_path.read_text(encoding="utf-8")
            normalized = report.replace(str(root), "<TMP>")
            expected = (
                Path(__file__).parent / "fixtures" / "expected_report.md"
            ).read_text(encoding="utf-8")
            self.assertEqual(normalized, expected)

            second_report_code, _ = self._run(
                ["report", "--session", str(session_path)], trusted_home=home
            )
            self.assertEqual(second_report_code, 0)
            self.assertEqual(report_path.read_text(encoding="utf-8"), report)

    @staticmethod
    def _run(argv: list[str], *, trusted_home: Path) -> tuple[int, str]:
        output = io.StringIO()
        with redirect_stdout(output):
            code = main(argv, trusted_home=trusted_home)
        return code, output.getvalue().strip()

    @staticmethod
    def _write(path: Path, content: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(content)

    @staticmethod
    def _snapshot(root: Path) -> tuple[tuple[str, str, bytes | None], ...]:
        entries: list[tuple[str, str, bytes | None]] = []
        for path in sorted(root.rglob("*")):
            relative = str(path.relative_to(root))
            if path.is_dir():
                entries.append((relative, "directory", None))
            else:
                entries.append((relative, "file", path.read_bytes()))
        return tuple(entries)


if __name__ == "__main__":
    unittest.main()
