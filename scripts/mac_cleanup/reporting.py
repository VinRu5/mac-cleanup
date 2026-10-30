"""Deterministic human reporting and durable operation accounting."""

from __future__ import annotations

from collections.abc import Mapping
from pathlib import Path
from typing import Any

from .admin_script import AdminArtifactValidation, validate_admin_artifacts
from .executor import BatchOutcome, _unresolved_mutation_intent_issue
from .jsonio import atomic_write_json, read_json
from .models import Issue, Manifest, Severity
from .sessions import Session, SessionConsistencyError


OUTCOMES_SCHEMA_VERSION = 1
ACCOUNTING_LOCK_LOST_CODE = "reporting.accounting-lock-lost"
_SEVERITY_ORDER = tuple(severity.value for severity in Severity)


class AdministrativeArtifactError(ValueError):
    """Raised when a bound manual artifact fails the Task 9 engine validator."""


class OutcomeLockIdentityError(SessionConsistencyError):
    """Raised when accounting no longer owns the current session-lock inode."""


def accounting_lock_loss_issue(state: Mapping[str, object]) -> Issue | None:
    """Return the durable accounting-lock stop without consulting outcomes."""
    candidates: list[object] = [state.get("critical_stop")]
    issues = state.get("issues", [])
    if isinstance(issues, list):
        candidates.extend(reversed(issues))
    for value in candidates:
        if not isinstance(value, Mapping):
            continue
        issue = Issue.from_dict(value)
        if issue.code == ACCOUNTING_LOCK_LOST_CODE:
            return issue
    return None


def validate_outcome_history(session: Session) -> None:
    """Strictly validate existing accounting without creating or changing it."""
    if not isinstance(session, Session):
        raise TypeError("session must be a Session")
    with session.operation_lock():
        manifest = session.read_manifest()
        document = _read_outcome_document(session)
        operations = document["operations"]
        assert isinstance(operations, list)
        _validate_operations_membership(manifest, operations)


def record_batch_outcome(
    session: Session, operation: str, outcome: BatchOutcome
) -> None:
    """Append one CLI engine result without changing authoritative lifecycle state."""
    if operation not in {"apply", "verify"}:
        raise ValueError("outcome operation must be apply or verify")
    if not isinstance(outcome, BatchOutcome):
        raise TypeError("outcome must be a BatchOutcome")
    if outcome.dry_run is not False:
        raise ValueError("dry-run outcomes must never be persisted")
    with session.operation_lock():
        manifest = session.read_manifest()
        _validate_outcome_membership(manifest, outcome)
        path = _outcomes_path(session)
        document = _read_outcome_document(session)
        operations = document["operations"]
        assert isinstance(operations, list)
        value = _outcome_value(len(operations) + 1, operation, outcome)
        _validate_outcome(value, len(operations) + 1)
        operations.append(value)
        _assert_outcome_lock_current(session)
        atomic_write_json(path, document)
        _assert_outcome_lock_current(session)


def render_report(
    session: Session, *, trusted_home: Path | None = None
) -> str:
    """Render stable Markdown from immutable manifest, lifecycle, and outcomes."""
    with session.operation_lock():
        return _render_report_locked(session, trusted_home)


def _render_report_locked(session: Session, trusted_home: Path | None) -> str:
    manifest = session.read_manifest()
    state = session.state
    intent = state.get("mutation_intent")
    if intent is not None and not isinstance(intent, Mapping):
        raise ValueError("session mutation intent is malformed")
    accounting_lost = accounting_lock_loss_issue(state)
    outcomes = (
        []
        if intent is not None or accounting_lost is not None
        else _read_outcome_document(session)["operations"]
    )
    assert isinstance(outcomes, list)
    _validate_operations_membership(manifest, outcomes)
    validations = (
        {}
        if intent is not None
        else _admin_validations(session, manifest, state, trusted_home)
    )

    lines = [
        "# Mac Cleanup Report",
        "",
        "> Logical target sizes are not net recovered space. Observed `df` free-space "
        "delta is reported separately and may differ because of APFS behavior and "
        "concurrent filesystem activity.",
        "",
    ]
    statuses = state.get("targets", {})
    if not isinstance(statuses, Mapping):
        raise ValueError("session target statuses are malformed")

    for batch in sorted(manifest.batches, key=lambda value: value.id):
        batch_outcomes = sorted(
            (item for item in outcomes if item["batch_id"] == batch.id),
            key=lambda item: item["sequence"],
        )
        apply_outcomes = [item for item in batch_outcomes if item["operation"] == "apply"]
        latest = batch_outcomes[-1] if batch_outcomes else None
        latest_apply = apply_outcomes[-1] if apply_outcomes else None
        removed_by_target = _removed_by_target(apply_outcomes)
        absent_ids = _absent_target_ids(apply_outcomes)
        uncertain_ids = _uncertain_target_ids(apply_outcomes)
        if intent is not None and intent.get("batch_id") == batch.id:
            target_id = intent.get("target_id")
            if isinstance(target_id, str):
                uncertain_ids.add(target_id)
        lines.extend(
            [
                f"## Batch `{batch.id}`",
                "",
                f"- Estimated logical bytes: {sum(target.logical_bytes for target in batch.targets)}",
                f"- Removed logical bytes: {_removed_total(apply_outcomes, absent_ids)}",
                f"- Removal accounting uncertainty: {_formatted_ids(uncertain_ids)}",
                f"- Observed `df` free-space delta: {_measurement(latest_apply, 'free_space_delta')}",
                f"- Regenerated bytes: {_measurement(latest, 'regenerated_bytes')}",
                f"- Regenerated target ids: {_ids(latest, 'regenerated_target_ids')}",
                "",
                "| Target id | Status | Estimated logical bytes | Removed logical bytes |",
                "|---|---:|---:|---:|",
            ]
        )
        for target in sorted(batch.targets, key=lambda value: value.id):
            removed: str | int = (
                "unknown"
                if target.id in uncertain_ids
                else removed_by_target.get(target.id, "unknown")
            )
            lines.append(
                f"| `{target.id}` | {statuses.get(target.id, 'unknown')} | "
                f"{target.logical_bytes} | {removed} |"
            )
        lines.append("")

    issues = list(_issues(manifest, state, outcomes))
    if intent is not None:
        issues.append(_unresolved_mutation_intent_issue(dict(intent)))
        issues = list({_issue_key(issue): issue for issue in issues}.values())
        issues.sort(key=_issue_key)
    lines.extend(["## Issues by severity", ""])
    for severity in _SEVERITY_ORDER:
        lines.extend([f"### {severity}", ""])
        grouped = [issue for issue in issues if issue.severity.value == severity]
        if not grouped:
            lines.append("- None")
        else:
            for issue in grouped:
                target = f" (`{issue.target_id}`)" if issue.target_id else ""
                lines.append(f"- `{issue.code}`{target}: {issue.message}")
        lines.append("")

    lines.extend(["## Administrative fallback", ""])
    bindings = state.get("admin_scripts", {})
    if not isinstance(bindings, Mapping):
        raise ValueError("session administrative bindings are malformed")
    if not bindings:
        lines.extend(["- None", ""])
    else:
        for batch_id in sorted(bindings):
            binding = bindings[batch_id]
            if not isinstance(binding, Mapping):
                raise ValueError("session administrative binding is malformed")
            if intent is not None:
                lines.append(
                    f"- `{batch_id}` validation blocked by unresolved mutation intent."
                )
                continue
            validation = validations[batch_id]
            batch = next(batch for batch in manifest.batches if batch.id == batch_id)
            batch_statuses = tuple(statuses.get(target.id) for target in batch.targets)
            authorized = "approved" in batch_statuses and all(
                status in {"approved", "verified"} for status in batch_statuses
            )
            lines.extend(_admin_lines(validation, authorized=authorized))
        lines.append("")

    lines.extend(["## Required user actions", ""])
    actions = _required_actions(manifest, state, statuses, validations)
    lines.extend(f"- {action}" for action in actions or ("None.",))
    lines.append("")
    return "\n".join(lines)


def _outcomes_path(session: Session) -> Path:
    return session.path / "outcomes.json"


def _assert_outcome_lock_current(session: Session) -> None:
    try:
        session.assert_operation_lock_current()
    except SessionConsistencyError as error:
        raise OutcomeLockIdentityError(
            "session lock identity changed during outcome accounting"
        ) from error


def _read_outcome_document(session: Session) -> dict[str, object]:
    """Read only while the path still names this operation's locked inode."""
    _assert_outcome_lock_current(session)
    path = _outcomes_path(session)
    if not path.exists():
        return {"schema_version": OUTCOMES_SCHEMA_VERSION, "operations": []}
    _assert_outcome_lock_current(session)
    return _read_outcomes(path)


def _outcome_value(
    sequence: int, operation: str, outcome: BatchOutcome
) -> dict[str, object]:
    removed = sorted(outcome.logical_bytes_removed_by_target)
    return {
        "batch_id": outcome.batch_id,
        "dry_run": outcome.dry_run,
        "free_space_after": outcome.free_space_after,
        "free_space_before": outcome.free_space_before,
        "free_space_delta": outcome.free_space_delta,
        "issues": [
            issue.to_dict()
            for issue in sorted(
                {_issue_key(issue): issue for issue in outcome.issues}.values(),
                key=_issue_key,
            )
        ],
        "logical_bytes_removed": outcome.logical_bytes_removed,
        "logical_bytes_removed_by_target": [
            {"logical_bytes_removed": count, "target_id": target_id}
            for target_id, count in removed
        ],
        "operation": operation,
        "regenerated_bytes": outcome.regenerated_bytes,
        "regenerated_target_ids": sorted(outcome.regenerated_target_ids),
        "sequence": sequence,
        "suspended": outcome.suspended,
        "uncertain_target_ids": sorted(outcome.uncertain_target_ids),
    }


def _read_outcomes(path: Path) -> dict[str, object]:
    value = read_json(path)
    if set(value) != {"schema_version", "operations"}:
        raise ValueError("outcomes fields do not match schema")
    if (
        type(value["schema_version"]) is not int
        or value["schema_version"] != OUTCOMES_SCHEMA_VERSION
    ):
        raise ValueError("outcomes schema_version must be 1")
    operations = value["operations"]
    if not isinstance(operations, list):
        raise ValueError("outcomes operations must be a list")
    for index, item in enumerate(operations, start=1):
        _validate_outcome(item, index)
    return value


def _validate_outcome(value: object, sequence: int) -> None:
    if not isinstance(value, Mapping):
        raise ValueError("outcome must be an object")
    expected = {
        "batch_id", "dry_run", "free_space_after", "free_space_before",
        "free_space_delta", "issues", "logical_bytes_removed",
        "logical_bytes_removed_by_target", "operation", "regenerated_bytes",
        "regenerated_target_ids", "sequence", "suspended",
        "uncertain_target_ids",
    }
    if (
        set(value) != expected
        or type(value["sequence"]) is not int
        or value["sequence"] != sequence
    ):
        raise ValueError("outcome fields or sequence do not match schema")
    if value["operation"] not in {"apply", "verify"}:
        raise ValueError("outcome operation is invalid")
    if not isinstance(value["batch_id"], str) or not value["batch_id"]:
        raise ValueError("outcome batch id is invalid")
    if value["dry_run"] is not False:
        raise ValueError("persisted outcomes must not be dry runs")
    if type(value["suspended"]) is not bool:
        raise ValueError("outcome boolean is invalid")
    total = value["logical_bytes_removed"]
    if total is not None and (type(total) is not int or total < 0):
        raise ValueError("outcome byte count is invalid")
    if type(value["regenerated_bytes"]) is not int or value["regenerated_bytes"] < 0:
        raise ValueError("outcome byte count is invalid")
    for key in ("free_space_before", "free_space_after", "free_space_delta"):
        if value[key] is not None and type(value[key]) is not int:
            raise ValueError("outcome free-space measurement is invalid")
    before = value["free_space_before"]
    after = value["free_space_after"]
    delta = value["free_space_delta"]
    if before is None or after is None:
        if before is not None or after is not None or delta is not None:
            raise ValueError("outcome free-space unknowns are inconsistent")
    elif before < 0 or after < 0 or delta != after - before:
        raise ValueError("outcome free-space accounting is inconsistent")
    issues = value["issues"]
    if not isinstance(issues, list):
        raise ValueError("outcome issues are invalid")
    parsed_issues: list[Issue] = []
    for issue in issues:
        if not isinstance(issue, Mapping):
            raise ValueError("outcome issue is invalid")
        parsed = Issue.from_dict(issue)
        if (
            dict(issue) != parsed.to_dict()
            or not parsed.code
            or not parsed.message
            or (
                parsed.target_id is not None
                and (
                    not isinstance(parsed.target_id, str)
                    or not parsed.target_id
                )
            )
        ):
            raise ValueError("outcome issue does not match schema")
        parsed_issues.append(parsed)
    issue_keys = [_issue_key(issue) for issue in parsed_issues]
    if (
        [dict(issue) for issue in issues]
        != [issue.to_dict() for issue in sorted(parsed_issues, key=_issue_key)]
        or len(issue_keys) != len(set(issue_keys))
    ):
        raise ValueError("outcome issues are not canonical and unique")
    removed = value["logical_bytes_removed_by_target"]
    if not isinstance(removed, list):
        raise ValueError("outcome target removals are invalid")
    seen: set[str] = set()
    for item in removed:
        if not isinstance(item, Mapping) or set(item) != {"target_id", "logical_bytes_removed"}:
            raise ValueError("outcome target removal is invalid")
        target_id = item["target_id"]
        count = item["logical_bytes_removed"]
        if (
            not isinstance(target_id, str)
            or not target_id
            or target_id in seen
            or type(count) is not int
            or count < 0
        ):
            raise ValueError("outcome target removal is invalid")
        seen.add(target_id)
    if [item["target_id"] for item in removed] != sorted(seen):
        raise ValueError("outcome target removals are not sorted")
    ids = value["regenerated_target_ids"]
    if (
        not isinstance(ids, list)
        or ids != sorted(set(ids))
        or not all(isinstance(item, str) and item for item in ids)
    ):
        raise ValueError("outcome regenerated target ids are invalid")
    uncertain = value["uncertain_target_ids"]
    if (
        not isinstance(uncertain, list)
        or uncertain != sorted(set(uncertain))
        or not all(isinstance(item, str) and item for item in uncertain)
        or bool(uncertain) != (total is None)
        or (uncertain and value["operation"] != "apply")
        or set(uncertain).intersection(seen)
    ):
        raise ValueError("outcome uncertain target ids are invalid")
    issue_uncertain = {
        issue.target_id
        for issue in parsed_issues
        if issue.code == "executor.removal-accounting-uncertain"
    }
    if issue_uncertain != set(uncertain):
        raise ValueError("outcome uncertainty does not match its issues")


def _validate_outcome_membership(manifest: Manifest, outcome: BatchOutcome) -> None:
    batches = {batch.id: batch for batch in manifest.batches}
    batch = batches.get(outcome.batch_id)
    if batch is None:
        raise ValueError("outcome names an unknown manifest batch")
    target_ids = {target.id for target in batch.targets}
    referenced = {
        target_id for target_id, _ in outcome.logical_bytes_removed_by_target
    } | set(outcome.regenerated_target_ids) | set(outcome.uncertain_target_ids) | {
        issue.target_id for issue in outcome.issues if issue.target_id is not None
    }
    if not referenced.issubset(target_ids):
        raise ValueError("outcome names a target outside its manifest batch")
    if (
        outcome.logical_bytes_removed is not None
        and sum(count for _, count in outcome.logical_bytes_removed_by_target)
        != outcome.logical_bytes_removed
    ):
        raise ValueError("outcome target removals do not equal its batch total")


def _validate_operations_membership(
    manifest: Manifest, operations: list[Mapping[str, Any]]
) -> None:
    batches = {batch.id: batch for batch in manifest.batches}
    for operation in operations:
        batch = batches.get(operation["batch_id"])
        if batch is None:
            raise ValueError("recorded outcome names an unknown manifest batch")
        target_ids = {target.id for target in batch.targets}
        removed = operation["logical_bytes_removed_by_target"]
        referenced = {item["target_id"] for item in removed}
        referenced.update(operation["regenerated_target_ids"])
        referenced.update(operation["uncertain_target_ids"])
        referenced.update(
            issue["target_id"]
            for issue in operation["issues"]
            if isinstance(issue.get("target_id"), str)
        )
        if not referenced.issubset(target_ids):
            raise ValueError("recorded outcome names a target outside its manifest batch")
        if (
            operation["logical_bytes_removed"] is not None
            and sum(item["logical_bytes_removed"] for item in removed)
            != operation["logical_bytes_removed"]
        ):
            raise ValueError("recorded target removals do not equal the batch total")


def _admin_validations(
    session: Session,
    manifest: Manifest,
    state: Mapping[str, object],
    trusted_home: Path | None,
) -> dict[str, AdminArtifactValidation]:
    bindings = state.get("admin_scripts", {})
    statuses = state.get("targets", {})
    if not isinstance(bindings, Mapping) or not isinstance(statuses, Mapping):
        raise ValueError("session administrative state is malformed")
    validations: dict[str, AdminArtifactValidation] = {}
    batches = {batch.id: batch for batch in manifest.batches}
    for batch_id in sorted(bindings):
        batch = batches.get(batch_id)
        if batch is None:
            raise ValueError("administrative binding names an unknown batch")
        try:
            validations[batch_id] = validate_admin_artifacts(
                session,
                batch_id,
                trusted_home=trusted_home,
                require_approved=False,
            )
        except (OSError, TypeError, ValueError) as error:
            raise AdministrativeArtifactError(
                f"administrative artifacts failed engine validation: {batch_id}"
            ) from error
    return validations


def _admin_lines(
    validation: AdminArtifactValidation, *, authorized: bool
) -> list[str]:
    lines = [
        f"- `{validation.batch_id}` engine validation: passed",
        f"  - Exact script: `{validation.script_path}`",
        f"  - Validated SHA-256: `{validation.checksum}`",
    ]
    if authorized:
        lines.append(
            "  - Manual precondition: execute exactly that validated script path, not a copy "
            "or replacement, only after confirming this checksum."
        )
    else:
        lines.append(
            "  - Lifecycle: integrity passed, but this batch is not currently authorized "
            "for manual execution."
        )
    lines.append(
        "  - Boundary: validation does not close the later manual validation-to-execution "
        "gap against a malicious same-UID actor."
    )
    return lines


def _required_actions(
    manifest: Manifest,
    state: Mapping[str, object],
    statuses: Mapping[str, object],
    validations: Mapping[str, AdminArtifactValidation],
) -> tuple[str, ...]:
    actions: list[str] = []
    intent = state.get("mutation_intent")
    if isinstance(intent, Mapping):
        return (
            "Stop all cleanup. Removed logical bytes are unknown for "
            f"`{intent.get('target_id')}`. Start a fresh session, rescan the "
            "filesystem, and obtain a new approval before any further mutation.",
        )
    critical = state.get("critical_stop")
    if critical is not None:
        if not isinstance(critical, Mapping):
            raise ValueError("session critical stop is malformed")
        issue = Issue.from_dict(critical)
        actions.append(
            f"Stop all mutation and inspect critical issue `{issue.code}` before creating "
            "a new session or manifest."
        )
    for batch in sorted(manifest.batches, key=lambda value: value.id):
        validation = validations.get(batch.id)
        batch_statuses = tuple(statuses.get(target.id) for target in batch.targets)
        if (
            validation is not None
            and "approved" in batch_statuses
            and all(
                status in {"approved", "verified"} for status in batch_statuses
            )
        ):
            actions.append(
                f"For `{batch.id}`, confirm SHA-256 `{validation.checksum}`, then execute "
                f"exactly `{validation.script_path}` and run `verify --batch {batch.id}` "
                "to import and recheck its results."
            )
        for target in sorted(batch.targets, key=lambda value: value.id):
            status = statuses.get(target.id)
            if status == "pending":
                actions.append(
                    f"Review `{target.id}` in `{batch.id}` and approve the batch's exact digest."
                )
            elif status == "approved" and validation is None:
                actions.append(
                    f"Run a dry-run, then apply approved target `{target.id}` in `{batch.id}`."
                )
            elif status == "suspended":
                actions.append(
                    f"Create a new session and rescan `{target.id}`; review the divergence and "
                    "approve a new manifest digest before retrying."
                )
            elif status == "failed":
                actions.append(f"Inspect the failure for `{target.id}`; do not retry unchanged.")
    return tuple(actions)


def _removed_by_target(outcomes: list[Mapping[str, Any]]) -> dict[str, int]:
    result: dict[str, int] = {}
    for outcome in outcomes:
        for item in outcome["logical_bytes_removed_by_target"]:
            target_id = item["target_id"]
            result[target_id] = result.get(target_id, 0) + item["logical_bytes_removed"]
    return result


def _absent_target_ids(outcomes: list[Mapping[str, Any]]) -> set[str]:
    return {
        issue["target_id"]
        for outcome in outcomes
        for issue in outcome["issues"]
        if issue.get("code") == "executor.target-absent" and isinstance(issue.get("target_id"), str)
    }


def _removed_total(
    outcomes: list[Mapping[str, Any]], absent_ids: set[str]
) -> str | int:
    if not outcomes:
        return "unknown"
    if any(outcome["logical_bytes_removed"] is None for outcome in outcomes):
        return "unknown"
    removed_records = [
        item
        for outcome in outcomes
        for item in outcome["logical_bytes_removed_by_target"]
    ]
    if absent_ids and not removed_records:
        return "unknown"
    return sum(outcome["logical_bytes_removed"] for outcome in outcomes)


def _uncertain_target_ids(outcomes: list[Mapping[str, Any]]) -> set[str]:
    return {
        target_id
        for outcome in outcomes
        for target_id in outcome["uncertain_target_ids"]
    }


def _formatted_ids(values: set[str]) -> str:
    return ", ".join(f"`{value}`" for value in sorted(values)) if values else "none"


def _measurement(
    outcome: Mapping[str, Any] | None, key: str
) -> str | int:
    if outcome is None or outcome[key] is None:
        return "unknown"
    return outcome[key]


def _ids(outcome: Mapping[str, Any] | None, key: str) -> str:
    if outcome is None:
        return "unknown"
    values = outcome[key]
    return ", ".join(f"`{value}`" for value in values) if values else "none"


def _issues(
    manifest: Manifest,
    state: Mapping[str, object],
    outcomes: list[Mapping[str, Any]],
) -> tuple[Issue, ...]:
    values: list[Issue] = list(manifest.issues)
    state_issues = state.get("issues", [])
    if not isinstance(state_issues, list):
        raise ValueError("session issues are malformed")
    for value in state_issues:
        if not isinstance(value, Mapping):
            raise ValueError("session issue is malformed")
        values.append(Issue.from_dict(value))
    for outcome in outcomes:
        values.extend(Issue.from_dict(value) for value in outcome["issues"])
    unique = {(_issue_key(issue)): issue for issue in values}
    return tuple(unique[key] for key in sorted(unique))


def _issue_key(issue: Issue) -> tuple[str, str, str, str]:
    return issue.severity.value, issue.code, issue.target_id or "", issue.message
