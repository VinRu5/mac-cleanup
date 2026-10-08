"""Command-line interface for the mac-cleanup skill."""

from __future__ import annotations

import argparse
from collections.abc import Sequence

COMMANDS = ("scan", "plan", "approve", "apply", "verify", "report")


def build_parser() -> argparse.ArgumentParser:
    """Build the parser for the explicit mac-cleanup command set."""
    parser = argparse.ArgumentParser(prog="mac-cleanup")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in COMMANDS:
        child = subparsers.add_parser(command)
        child.add_argument("--session", required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Parse command-line arguments and return a process status code."""
    build_parser().parse_args(argv)
    return 0
