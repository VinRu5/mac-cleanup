"""Command-line interface for the mac-cleanup skill."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
import os
from pathlib import Path
import pwd

from .executor import apply_batch, verify_batch
from .manifests import approve_batch
from .models import Batch
from .sessions import InvalidTransition, Session

COMMANDS = ("scan", "plan", "approve", "apply", "verify", "report")


def build_parser() -> argparse.ArgumentParser:
    """Build the parser for the explicit mac-cleanup command set."""
    parser = argparse.ArgumentParser(prog="mac-cleanup")
    subparsers = parser.add_subparsers(dest="command", required=True)
    for command in COMMANDS:
        child = subparsers.add_parser(command)
        child.add_argument("--session", required=True)
        if command in {"approve", "apply", "verify"}:
            child.add_argument("--batch", required=True)
        if command == "approve":
            child.add_argument("--digest", required=True)
        if command == "apply":
            child.add_argument("--dry-run", action="store_true")
    return parser


def main(
    argv: Sequence[str] | None = None, *, trusted_home: Path | None = None
) -> int:
    """Parse command-line arguments and return a process status code."""
    args = build_parser().parse_args(argv)
    if args.command == "approve":
        try:
            approve_batch(Session.load(args.session), args.batch, args.digest)
        except (FileNotFoundError, InvalidTransition, KeyError, ValueError):
            return 2
    elif args.command in {"apply", "verify"}:
        try:
            session = Session.load(args.session)
            batch = _named_batch(session, args.batch)
            roots = _trusted_allowed_roots(batch, trusted_home or _current_home())
            if args.command == "apply":
                outcome = apply_batch(session, batch, roots, dry_run=args.dry_run)
            else:
                outcome = verify_batch(session, batch, roots)
            if outcome.suspended or any(
                issue.severity.value in {"batch_error", "critical"}
                for issue in outcome.issues
            ):
                return 2
        except (FileNotFoundError, InvalidTransition, KeyError, OSError, ValueError):
            return 2
    return 0


def _named_batch(session: Session, batch_id: str) -> Batch:
    matches = tuple(
        batch for batch in session.read_manifest().batches if batch.id == batch_id
    )
    if len(matches) != 1:
        raise ValueError(f"unknown manifest batch: {batch_id}")
    return matches[0]


def _current_home() -> Path:
    """Return the account database home, independent of caller environment."""
    return Path(pwd.getpwuid(os.getuid()).pw_dir)


def _trusted_allowed_roots(batch: Batch, home: Path) -> tuple[Path, ...]:
    """Map fixed module identities to roots trusted independently of targets."""
    modules = {target.id.partition(":")[0] for target in batch.targets}
    if modules != {"user-caches"}:
        raise ValueError("batch does not map to a supported trusted module root")
    if not home.is_absolute():
        raise ValueError("trusted home must be absolute")
    return (home / "Library" / "Caches",)
