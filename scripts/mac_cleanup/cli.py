"""Command-line orchestration for the deterministic mac-cleanup engine."""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
import json
import os
from pathlib import Path
import pwd

from .admin_script import generate_admin_script, import_admin_results
from .executor import BatchOutcome, apply_batch, verify_batch
from .manifests import approval_digest, approve_batch, build_manifest
from .models import Batch, Issue, Severity, Target
from .modules.base import ScanContext, ScanResult
from .modules.registry import registered_modules
from .process import ProcessRunner, ToolResolver
from .reporting import (
    AdministrativeArtifactError,
    record_batch_outcome,
    render_report,
)
from .sessions import InvalidTransition, Session


COMMANDS = ("scan", "plan", "approve", "apply", "verify", "report")
SUCCESS = 0
INVALID_INPUT = 2
BATCH_SUSPENDED = 3
CRITICAL_SAFETY_FAILURE = 4
DEFAULT_POLICY = {
    "schema_version": 1,
    "enabled_modules": ["user-caches"],
    "preserve_target_ids": [],
    "allow_review_required": False,
    "deep_scan_threshold_bytes": 1_073_741_824,
}


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
    """Run one command and return 0, 2, 3, or 4 without raising user errors."""
    args = build_parser().parse_args(argv)
    home = trusted_home or _current_home()
    try:
        if args.command == "scan":
            return _scan(Path(args.session), home)
        if args.command == "plan":
            return _plan(Path(args.session))
        if args.command == "approve":
            session = Session.load(args.session)
            approve_batch(session, args.batch, args.digest)
            _print_json({"batch_id": args.batch, "command": "approve", "status": "approved"})
            return SUCCESS
        if args.command == "apply":
            return _apply(Path(args.session), args.batch, args.dry_run, home)
        if args.command == "verify":
            return _verify(Path(args.session), args.batch, home)
        if args.command == "report":
            session = Session.load(args.session)
            with session.operation_lock():
                report = render_report(session, trusted_home=home)
                session.write_report(report)
            print(session.report_path)
            return SUCCESS
    except AdministrativeArtifactError:
        return CRITICAL_SAFETY_FAILURE
    except (FileNotFoundError, InvalidTransition, KeyError, OSError, TypeError, ValueError):
        return INVALID_INPUT
    return INVALID_INPUT


def _scan(session_path: Path, home: Path) -> int:
    session = Session.load(session_path) if (session_path / "state.json").exists() else Session.create(session_path)
    if session.policy_path.exists():
        policy = session.read_policy()
    else:
        policy = dict(DEFAULT_POLICY)
        session.write_policy(policy)
    threshold = policy.get("deep_scan_threshold_bytes")
    if type(threshold) is not int or threshold < 0:
        raise ValueError("policy deep_scan_threshold_bytes must be a non-negative integer")
    canonical_home = _canonical_home(home)
    context = ScanContext(
        home=canonical_home,
        uid=os.getuid(),
        runner=ProcessRunner(),
        deep_scan_threshold=threshold,
        timeout_seconds=5,
    )
    targets: dict[str, Target] = {}
    issues: list[Issue] = []
    executable_ids: set[str] = set()
    modules: list[dict[str, object]] = []
    resolver = ToolResolver()
    for module in registered_modules():
        detected = module.detect(context)
        modules.append({"detected": detected, "id": module.id})
        if not detected:
            continue
        fast = module.fast_scan(context)
        issues.extend(fast.issues)
        targets.update((target.id, target) for target in fast.targets)
        deep = module.deep_scan(context, tuple(target.id for target in fast.targets))
        issues.extend(deep.issues)
        targets.update((target.id, target) for target in deep.targets)
        executable_ids.update(deep.executable_target_ids)
    inventory = {
        "capabilities": {
            "modules": modules,
            "tools": [
                {"available": resolver.resolve(name) is not None, "name": name}
                for name in ("python3", "zsh")
            ],
        },
        "executable_target_ids": sorted(executable_ids),
        "issues": [issue.to_dict() for issue in sorted(issues, key=_issue_key)],
        "schema_version": 1,
        "targets": [target.to_dict() for target in sorted(targets.values(), key=lambda value: value.id)],
    }
    session.write_inventory(inventory)
    _print_json(
        {
            "capabilities": inventory["capabilities"],
            "command": "scan",
            "detected_modules": [item["id"] for item in modules if item["detected"]],
            "executable_target_ids": inventory["executable_target_ids"],
            "inventory_path": str(session.inventory_path),
            "issue_count": len(issues),
        }
    )
    return SUCCESS


def _plan(session_path: Path) -> int:
    session = Session.load(session_path)
    with session.operation_lock():
        inventory = _scan_result(session.read_inventory())
        manifest = build_manifest(inventory, session.read_policy())
        session.write_manifest(manifest)
    summaries = []
    for batch in sorted(manifest.batches, key=lambda value: value.id):
        summaries.append(
            {
                "approval_digest": approval_digest(manifest, batch.id),
                "estimated_logical_bytes": sum(target.logical_bytes for target in batch.targets),
                "id": batch.id,
                "target_ids": [target.id for target in sorted(batch.targets, key=lambda value: value.id)],
            }
        )
    _print_json(
        {
            "batches": summaries,
            "command": "plan",
            "manifest_path": str(session.manifest_path),
        }
    )
    return SUCCESS


def _apply(session_path: Path, batch_id: str, dry_run: bool, home: Path) -> int:
    session = Session.load(session_path)
    batch = _named_batch(session, batch_id)
    roots = _trusted_allowed_roots(batch, _canonical_home(home))
    if dry_run:
        outcome = apply_batch(session, batch, roots, dry_run=True)
        _print_json(_outcome_summary("apply", outcome))
        return _outcome_exit(outcome)

    preview = apply_batch(session, batch, roots, dry_run=True)
    if _administrative_fallback_required(preview):
        script_path = session.path / f"admin-{batch.id}.zsh"
        result_path = session.path / f"admin-{batch.id}-result.json"
        try:
            checksum = generate_admin_script(
                batch,
                script_path,
                result_path,
                trusted_home=home,
            )
        except (OSError, TypeError, ValueError):
            _print_json(
                {
                    "batch_id": batch.id,
                    "command": "apply",
                    "critical_issue": "administrative artifact validation failed",
                }
            )
            return CRITICAL_SAFETY_FAILURE
        _print_json(
            {
                "batch_id": batch.id,
                "checksum": checksum,
                "command": "apply",
                "manual_precondition": (
                    "Execute exactly the engine-validated script path, not a copy or "
                    "replacement, only after confirming this checksum. Validation does not "
                    "close the later same-UID manual execution gap."
                ),
                "result_path": str(result_path),
                "script_path": str(script_path),
                "status": "administrative_fallback_required",
            }
        )
        return BATCH_SUSPENDED

    outcome = apply_batch(session, batch, roots)
    record_batch_outcome(session, "apply", outcome)
    _print_json(_outcome_summary("apply", outcome))
    return _outcome_exit(outcome)


def _verify(session_path: Path, batch_id: str, home: Path) -> int:
    session = Session.load(session_path)
    binding = session.admin_script_binding(batch_id)
    if binding is not None:
        result_path = binding.get("result_path")
        checksum = binding.get("checksum")
        if not isinstance(result_path, str) or not isinstance(checksum, str):
            raise ValueError("administrative binding is malformed")
        try:
            import_admin_results(
                session,
                result_path,
                checksum,
                trusted_home=home,
            )
        except (OSError, TypeError, ValueError):
            _print_json(
                {
                    "batch_id": batch_id,
                    "command": "verify",
                    "critical_issue": "administrative artifact validation failed",
                }
            )
            return CRITICAL_SAFETY_FAILURE
        session = Session.load(session_path)
        critical = session.critical_issue()
        if critical is not None:
            _print_json({"batch_id": batch_id, "command": "verify", "critical_issue": critical.to_dict()})
            return CRITICAL_SAFETY_FAILURE
        batch = _named_batch(session, batch_id)
        statuses = tuple(session.status(target.id) for target in batch.targets)
        if any(status == "suspended" for status in statuses):
            _print_json({"batch_id": batch_id, "command": "verify", "status": "suspended"})
            return BATCH_SUSPENDED
    batch = _named_batch(session, batch_id)
    roots = _trusted_allowed_roots(batch, _canonical_home(home))
    outcome = verify_batch(session, batch, roots)
    record_batch_outcome(session, "verify", outcome)
    _print_json(_outcome_summary("verify", outcome))
    return _outcome_exit(outcome)


def _scan_result(value: Mapping[str, object]) -> ScanResult:
    expected = {"capabilities", "executable_target_ids", "issues", "schema_version", "targets"}
    if set(value) != expected or value.get("schema_version") != 1:
        raise ValueError("inventory fields do not match schema version 1")
    capabilities = value["capabilities"]
    targets = value["targets"]
    issues = value["issues"]
    executable = value["executable_target_ids"]
    if not isinstance(capabilities, Mapping) or not isinstance(targets, list) or not isinstance(issues, list):
        raise ValueError("inventory is malformed")
    if not isinstance(executable, list) or not all(isinstance(item, str) for item in executable):
        raise ValueError("inventory executable target ids are malformed")
    if not all(isinstance(item, Mapping) for item in targets + issues):
        raise ValueError("inventory targets or issues are malformed")
    return ScanResult(
        targets=tuple(Target.from_dict(item) for item in targets),
        issues=tuple(Issue.from_dict(item) for item in issues),
        executable_target_ids=tuple(executable),
    )


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


def _canonical_home(home: Path) -> Path:
    if not home.is_absolute() or ".." in home.parts:
        raise ValueError("trusted home must be absolute and canonical")
    canonical = home.resolve(strict=True)
    if canonical != home or not canonical.is_dir():
        raise ValueError("trusted home must be an existing canonical directory")
    return canonical


def _trusted_allowed_roots(batch: Batch, home: Path) -> tuple[Path, ...]:
    """Map fixed module identities to roots trusted independently of targets."""
    modules = {target.id.partition(":")[0] for target in batch.targets}
    if modules != {"user-caches"}:
        raise ValueError("batch does not map to a supported trusted module root")
    cache_root = home / "Library" / "Caches"
    if cache_root.resolve(strict=True) != cache_root or not cache_root.is_dir():
        raise ValueError("trusted cache root must be an existing canonical directory")
    return (cache_root,)


def _administrative_fallback_required(outcome: BatchOutcome) -> bool:
    blocking = tuple(
        issue for issue in outcome.issues
        if issue.severity in {Severity.BATCH_ERROR, Severity.CRITICAL}
    )
    return bool(blocking) and all(
        issue.code == "executor.permission-denied" for issue in blocking
    )


def _outcome_exit(outcome: BatchOutcome) -> int:
    if any(issue.severity is Severity.CRITICAL for issue in outcome.issues):
        return CRITICAL_SAFETY_FAILURE
    if outcome.suspended or any(
        issue.severity is Severity.BATCH_ERROR for issue in outcome.issues
    ):
        return BATCH_SUSPENDED
    return SUCCESS


def _outcome_summary(command: str, outcome: BatchOutcome) -> dict[str, object]:
    return {
        "batch_id": outcome.batch_id,
        "command": command,
        "dry_run": outcome.dry_run,
        "free_space_delta": outcome.free_space_delta,
        "issues": [issue.to_dict() for issue in sorted(outcome.issues, key=_issue_key)],
        "logical_bytes_removed": outcome.logical_bytes_removed,
        "regenerated_bytes": outcome.regenerated_bytes,
        "regenerated_target_ids": sorted(outcome.regenerated_target_ids),
        "status": "suspended" if outcome.suspended else "success",
    }


def _issue_key(issue: Issue) -> tuple[str, str, str, str]:
    return issue.severity.value, issue.code, issue.target_id or "", issue.message


def _print_json(value: Mapping[str, object]) -> None:
    print(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
