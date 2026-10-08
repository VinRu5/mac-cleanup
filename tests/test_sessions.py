import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts.mac_cleanup.jsonio import atomic_write_json, read_json
from scripts.mac_cleanup.models import Batch, Issue, Manifest, Risk, Severity, Target
from scripts.mac_cleanup.sessions import InvalidTransition, Session


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


if __name__ == "__main__":
    unittest.main()
