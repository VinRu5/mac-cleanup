"""Command-line orchestration for the deterministic mac-cleanup engine."""

from __future__ import annotations

import argparse
from collections.abc import Mapping, Sequence
import json
import os
from pathlib import Path
import pwd
import re

from .admin_script import generate_admin_script, import_admin_results
from .executor import (
    BatchOutcome,
    _unresolved_mutation_intent_issue,
    apply_batch,
    verify_batch,
)
from .manifests import approval_digest, approve_batch, build_manifest
from .models import Batch, Issue, Severity, Target, TargetStatus
from .modules.base import ScanContext, ScanResult
from .modules.registry import registered_modules
from .process import ProcessRunner, ToolResolver
from .reporting import (
    ACCOUNTING_LOCK_LOST_CODE,
    AdministrativeArtifactError,
    OutcomeLockIdentityError,
    accounting_lock_loss_issue,
    record_batch_outcome,
    render_report,
    validate_outcome_history,
)
from .sessions import InvalidTransition, Session, SessionConsistencyError


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
            return _report(Path(args.session), home)
    except AdministrativeArtifactError:
        return CRITICAL_SAFETY_FAILURE
    except (FileNotFoundError, InvalidTransition, KeyError, OSError, TypeError, ValueError):
        return INVALID_INPUT
    return INVALID_INPUT


def _scan(session_path: Path, home: Path) -> int:
    session = Session.load(session_path) if (session_path / "state.json").exists() else Session.create(session_path)
    with session.operation_lock():
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
            if not fast.targets:
                continue
            deep = module.deep_scan(context, tuple(target.id for target in fast.targets))
            issues.extend(deep.issues)
            targets.update((target.id, target) for target in deep.targets)
            executable_ids.update(deep.executable_target_ids)
        inventory = {
            "capabilities": {
                "modules": sorted(modules, key=lambda item: str(item["id"])),
                "tools": [
                    {"available": resolver.resolve(name) is not None, "name": name}
                    for name in ("python3", "zsh")
                ],
            },
            "executable_target_ids": sorted(executable_ids),
            "issues": [issue.to_dict() for issue in sorted(issues, key=_issue_key)],
            "schema_version": 1,
            "targets": [
                target.to_dict()
                for target in sorted(targets.values(), key=lambda value: value.id)
            ],
        }
        _scan_result(inventory)
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
    mutation_may_have_completed = False
    try:
        with session.operation_lock():
            unresolved = session.mutation_intent()
            if unresolved is not None:
                return _critical_accounting_stop(
                    "apply",
                    batch_id,
                    _unresolved_mutation_intent_issue(unresolved),
                )
            existing = accounting_lock_loss_issue(session.state)
            if existing is not None:
                return _critical_accounting_stop("apply", batch_id, existing)
            validate_outcome_history(session)
            batch = _named_batch(session, batch_id)
            roots = _trusted_allowed_roots(batch, _canonical_home(home))
            if dry_run:
                outcome = apply_batch(session, batch, roots, dry_run=True)
                session.assert_operation_lock_current()
                _print_json(_outcome_summary("apply", outcome))
                return _outcome_exit(outcome)

            preview = apply_batch(session, batch, roots, dry_run=True)
            session.assert_operation_lock_current()
            if _administrative_fallback_required(preview):
                script_path = session.path / f"admin-{batch.id}.zsh"
                result_path = session.path / f"admin-{batch.id}-result.json"
                mutation_may_have_completed = True
                try:
                    checksum = generate_admin_script(
                        batch,
                        script_path,
                        result_path,
                        trusted_home=home,
                    )
                except SessionConsistencyError:
                    raise
                except (OSError, TypeError, ValueError):
                    _print_json(
                        {
                            "batch_id": batch.id,
                            "command": "apply",
                            "critical_issue": "administrative artifact validation failed",
                        }
                    )
                    return CRITICAL_SAFETY_FAILURE
                session.assert_operation_lock_current()
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

            mutation_may_have_completed = True
            outcome = apply_batch(
                session,
                batch,
                roots,
                outcome_recorder=lambda value: record_batch_outcome(
                    session, "apply", value
                ),
            )
            _print_json(_outcome_summary("apply", outcome))
            return _outcome_exit(outcome)
    except (OutcomeLockIdentityError, SessionConsistencyError):
        return _recover_accounting_lock_loss(
            session_path,
            "apply",
            batch_id,
            mutation_may_have_completed=mutation_may_have_completed,
        )


def _verify(session_path: Path, batch_id: str, home: Path) -> int:
    session = Session.load(session_path)
    mutation_may_have_completed = False
    try:
        with session.operation_lock():
            unresolved = session.mutation_intent()
            if unresolved is not None:
                return _critical_accounting_stop(
                    "verify",
                    batch_id,
                    _unresolved_mutation_intent_issue(unresolved),
                )
            existing = accounting_lock_loss_issue(session.state)
            if existing is not None:
                return _critical_accounting_stop("verify", batch_id, existing)
            validate_outcome_history(session)
            binding = session.admin_script_binding(batch_id)
            if binding is not None:
                result_path = binding.get("result_path")
                checksum = binding.get("checksum")
                if not isinstance(result_path, str) or not isinstance(checksum, str):
                    raise ValueError("administrative binding is malformed")
                mutation_may_have_completed = True
                try:
                    import_admin_results(
                        session,
                        result_path,
                        checksum,
                        trusted_home=home,
                    )
                except SessionConsistencyError:
                    raise
                except (OSError, TypeError, ValueError):
                    _print_json(
                        {
                            "batch_id": batch_id,
                            "command": "verify",
                            "critical_issue": "administrative artifact validation failed",
                        }
                    )
                    return CRITICAL_SAFETY_FAILURE
                session.assert_operation_lock_current()
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
            mutation_may_have_completed = True
            outcome = verify_batch(session, batch, roots)
            record_batch_outcome(session, "verify", outcome)
            _print_json(_outcome_summary("verify", outcome))
            return _outcome_exit(outcome)
    except (OutcomeLockIdentityError, SessionConsistencyError):
        return _recover_accounting_lock_loss(
            session_path,
            "verify",
            batch_id,
            mutation_may_have_completed=mutation_may_have_completed,
        )


def _report(session_path: Path, home: Path) -> int:
    session = Session.load(session_path)
    try:
        with session.operation_lock():
            unresolved = session.mutation_intent()
            report = render_report(session, trusted_home=home)
            session.assert_operation_lock_current()
            session.write_report(report)
            session.assert_operation_lock_current()
        print(session.report_path)
        return CRITICAL_SAFETY_FAILURE if unresolved is not None else SUCCESS
    except (OutcomeLockIdentityError, SessionConsistencyError):
        return _recover_accounting_lock_loss(
            session_path,
            "report",
            None,
            mutation_may_have_completed=False,
        )


def _recover_accounting_lock_loss(
    session_path: Path,
    operation: str,
    batch_id: str | None,
    *,
    mutation_may_have_completed: bool,
) -> int:
    """Reacquire the current lock and latch uncertainty without reading outcomes."""
    recovered = Session.load(session_path)
    with recovered.operation_lock():
        issue = accounting_lock_loss_issue(recovered.state)
        if issue is None:
            if mutation_may_have_completed:
                detail = (
                    "Filesystem or lifecycle mutation may have completed; rollback is "
                    "impossible and removed-logical accounting is unknown."
                )
            else:
                detail = (
                    "The loss was detected before cleanup mutation; target lifecycle and "
                    "filesystem contents were not changed by this command."
                )
            scope = f" for batch {batch_id}" if batch_id is not None else ""
            issue = Issue(
                ACCOUNTING_LOCK_LOST_CODE,
                Severity.CRITICAL,
                f"Session lock identity changed during {operation}{scope}. "
                f"{detail} Start a new session before any further cleanup.",
            )
            if recovered.critical_issue() is None:
                recovered.latch_critical(issue)
            else:
                recovered.add_issue(issue)
    return _critical_accounting_stop(operation, batch_id, issue)


def _critical_accounting_stop(
    operation: str, batch_id: str | None, issue: Issue
) -> int:
    value: dict[str, object] = {
        "command": operation,
        "critical_issue": issue.to_dict(),
        "status": "critical_safety_stop",
    }
    if batch_id is not None:
        value["batch_id"] = batch_id
    _print_json(value)
    return CRITICAL_SAFETY_FAILURE


def _scan_result(value: Mapping[str, object]) -> ScanResult:
    expected = {"capabilities", "executable_target_ids", "issues", "schema_version", "targets"}
    if (
        set(value) != expected
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != 1
    ):
        raise ValueError("inventory fields do not match schema version 1")
    capabilities = value["capabilities"]
    targets = value["targets"]
    issues = value["issues"]
    executable = value["executable_target_ids"]
    if (
        not isinstance(capabilities, Mapping)
        or set(capabilities) != {"modules", "tools"}
        or not isinstance(targets, list)
        or not isinstance(issues, list)
    ):
        raise ValueError("inventory is malformed")
    modules = capabilities["modules"]
    tools = capabilities["tools"]
    _validate_capability_records(modules, {"detected", "id"}, "detected")
    _validate_capability_records(tools, {"available", "name"}, "available")
    if (
        not isinstance(executable, list)
        or not all(isinstance(item, str) and item for item in executable)
        or executable != sorted(set(executable))
    ):
        raise ValueError("inventory executable target ids are malformed")
    if not all(isinstance(item, Mapping) for item in targets + issues):
        raise ValueError("inventory targets or issues are malformed")
    parsed_targets: list[Target] = []
    seen_ids: set[str] = set()
    for item in targets:
        if set(item) != {
            "id",
            "path",
            "kind",
            "risk",
            "status",
            "fingerprint",
            "logical_bytes",
        } or type(item["logical_bytes"]) is not int:
            raise ValueError("inventory target does not match schema")
        target = Target.from_dict(item)
        if dict(item) != target.to_dict():
            raise ValueError("inventory target does not match schema")
        if (
            not target.id
            or target.id in seen_ids
            or target.status is not TargetStatus.PENDING
            or target.kind not in {"file", "directory"}
            or type(target.logical_bytes) is not int
            or target.logical_bytes < 0
        ):
            raise ValueError("inventory target fields are invalid")
        prefix, separator, name = target.id.partition(":")
        raw_path = target.path
        path = Path(raw_path)
        if (
            not prefix
            or not separator
            or not name
            or not path.is_absolute()
            or ".." in path.parts
            or any(character in target.path for character in ("\0", "\n", "\r"))
        ):
            raise ValueError("inventory target identity is invalid")
        try:
            canonical_path = str(path.resolve(strict=False))
        except (OSError, RuntimeError) as error:
            raise ValueError("inventory target path cannot be resolved") from error
        if raw_path != canonical_path or path.name != name:
            raise ValueError("inventory target identity is invalid")
        if target.fingerprint and not re.fullmatch(r"[0-9a-f]{64}", target.fingerprint):
            raise ValueError("inventory target fingerprint is invalid")
        seen_ids.add(target.id)
        parsed_targets.append(target)
    if [target.id for target in parsed_targets] != sorted(seen_ids):
        raise ValueError("inventory targets are not sorted")
    executable_ids = set(executable)
    if not executable_ids.issubset(seen_ids):
        raise ValueError("inventory executable ids name unknown targets")
    if any(
        not target.fingerprint
        for target in parsed_targets
        if target.id in executable_ids
    ):
        raise ValueError("inventory executable target is shallow")
    parsed_issues: list[Issue] = []
    for item in issues:
        issue = Issue.from_dict(item)
        if dict(item) != issue.to_dict() or not issue.code or not issue.message:
            raise ValueError("inventory issue does not match schema")
        if issue.target_id is not None and (
            not isinstance(issue.target_id, str) or not issue.target_id
        ):
            raise ValueError("inventory issue target id is invalid")
        parsed_issues.append(issue)
    if parsed_issues != sorted(parsed_issues, key=_issue_key):
        raise ValueError("inventory issues are not sorted")
    issue_keys = [_issue_key(issue) for issue in parsed_issues]
    if len(issue_keys) != len(set(issue_keys)):
        raise ValueError("inventory issues are not unique")
    return ScanResult(
        targets=tuple(parsed_targets),
        issues=tuple(parsed_issues),
        executable_target_ids=tuple(executable),
    )


def _validate_capability_records(
    value: object, fields: set[str], boolean_field: str
) -> None:
    if not isinstance(value, list):
        raise ValueError("inventory capabilities must be lists")
    name_field = "id" if "id" in fields else "name"
    names: list[str] = []
    for item in value:
        if not isinstance(item, Mapping) or set(item) != fields:
            raise ValueError("inventory capability does not match schema")
        name = item[name_field]
        if (
            not isinstance(name, str)
            or not name
            or type(item[boolean_field]) is not bool
        ):
            raise ValueError("inventory capability fields are invalid")
        names.append(name)
    if names != sorted(set(names)):
        raise ValueError("inventory capabilities are not sorted and unique")


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
        "uncertain_target_ids": sorted(outcome.uncertain_target_ids),
    }


def _issue_key(issue: Issue) -> tuple[str, str, str, str]:
    return issue.severity.value, issue.code, issue.target_id or "", issue.message


def _print_json(value: Mapping[str, object]) -> None:
    print(json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False))
