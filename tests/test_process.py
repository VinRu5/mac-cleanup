import sys
import os
import tempfile
import unittest
from pathlib import Path

from scripts.mac_cleanup.process import OperationMode, ProcessRunner, ToolResolver


class ProcessTest(unittest.TestCase):
    def test_argv_python_command_succeeds_without_a_shell(self) -> None:
        result = ProcessRunner().run(
            (sys.executable, "-c", "print('ok')"), timeout_seconds=5
        )
        self.assertTrue(result.available)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout.strip(), "ok")
        self.assertFalse(result.timed_out)
        self.assertFalse(result.mutation)
        self.assertEqual(result.argv[0], sys.executable)

    def test_sleeping_command_is_reported_as_timed_out(self) -> None:
        result = ProcessRunner().run(
            (sys.executable, "-c", "import time; time.sleep(1)"), timeout_seconds=0.01
        )
        self.assertTrue(result.timed_out)
        self.assertIsNone(result.exit_code)
        self.assertGreaterEqual(result.duration_seconds, 0)

    def test_missing_executable_is_unavailable(self) -> None:
        result = ProcessRunner().run(("definitely-not-a-real-tool",), timeout_seconds=1)
        self.assertFalse(result.available)
        self.assertIsNone(result.exit_code)
        self.assertIn("unavailable", result.stderr)

    def test_string_commands_are_rejected(self) -> None:
        with self.assertRaises(TypeError):
            ProcessRunner().run("echo unsafe", timeout_seconds=1)  # type: ignore[arg-type]

    def test_resolver_uses_path_lookup(self) -> None:
        self.assertIsNotNone(ToolResolver().resolve(sys.executable))

    def test_scan_disallows_known_side_effecting_commands(self) -> None:
        for argv in (
            ("open", "/tmp/example"),
            ("adb", "-P", "5037", "devices"),
            ("env", "adb", "devices"),
            ("env", "-u", "HOME", "adb", "devices"),
            ("sudo", "-u", "root", "adb", "devices"),
            ("command", "-p", "adb", "devices"),
            ("exec", "-a", "adb", "adb", "devices"),
            ("brew", "cleanup"),
            ("npm", "cache", "clean", "--force"),
            ("yarn", "cache", "clean"),
            ("pip", "cache", "purge"),
        ):
            result = ProcessRunner().run(argv, timeout_seconds=1, mutation=False)
            self.assertTrue(result.disallowed, argv)
            self.assertIsNone(result.exit_code)

    def test_dry_run_package_cleanup_is_allowed_to_execute(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            executable = Path(directory) / "brew"
            executable.write_text("#!/bin/sh\nprintf 'dry-run-ok\\n'\n")
            executable.chmod(0o700)
            original_path = os.environ.get("PATH", "")
            os.environ["PATH"] = directory
            try:
                result = ProcessRunner().run(
                    ("brew", "cleanup", "--dry-run"), timeout_seconds=1
                )
            finally:
                os.environ["PATH"] = original_path
        self.assertFalse(result.disallowed)
        self.assertTrue(result.available)
        self.assertEqual(result.exit_code, 0)
        self.assertEqual(result.stdout.strip(), "dry-run-ok")

    def test_approved_mutation_mode_can_execute_a_command(self) -> None:
        result = ProcessRunner().run(
            (sys.executable, "-c", "print('approved')"),
            timeout_seconds=1,
            mode=OperationMode.APPROVED_MUTATION,
        )
        self.assertFalse(result.disallowed)
        self.assertTrue(result.mutation)
        self.assertEqual(result.stdout.strip(), "approved")


if __name__ == "__main__":
    unittest.main()
