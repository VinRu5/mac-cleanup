import unittest

from scripts.mac_cleanup.cli import build_parser


class CliTest(unittest.TestCase):
    def test_commands_are_explicit(self) -> None:
        parser = build_parser()
        for command in ("scan", "plan", "approve", "apply", "verify", "report"):
            with self.subTest(command=command):
                value = parser.parse_args([command, "--session", "/tmp/session"])
                self.assertEqual(value.command, command)
