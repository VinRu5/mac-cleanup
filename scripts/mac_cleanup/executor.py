"""Preflight, exact application, and verification of approved cleanup batches."""

from __future__ import annotations

from dataclasses import dataclass, field
import errno
import fcntl
import os
from pathlib import Path
import shutil
import stat
from typing import Iterable

from .models import Batch, Issue, Severity, Target
from .paths import PathIdentity, PathSafetyError, inspect_path, remove_tree_exact
from .sessions import Session


@dataclass(frozen=True)
class BatchOutcome:
    """Structured result for one named batch operation."""

    batch_id: str
    issues: tuple[Issue, ...] = field(default_factory=tuple)
    logical_bytes_removed: int = 0
    free_space_before: int | None = None
    free_space_after: int | None = None
    dry_run: bool = False
    suspended: bool = False

    @property
    def free_space_delta(self) -> int | None:
        if self.free_space_before is None or self.free_space_after is None:
            return None
        return self.free_space_after - self.free_space_before


@dataclass(frozen=True)
class _Preflight:
    target: Target
    identity: PathIdentity | None = None
    issues: tuple[Issue, ...] = field(default_factory=tuple)

    @property
    def absent(self) -> bool:
        return any(issue.code == "executor.target-absent" for issue in self.issues)


def preflight_target(
    target: Target, allowed_roots: Iterable[str | os.PathLike[str]]
) -> tuple[Issue, ...]:
    """Return deterministic safety issues for one immutable manifest target."""
    return _preflight_target(target, tuple(allowed_roots)).issues


def apply_batch(
    session: Session,
    batch: Batch,
    allowed_roots: Iterable[str | os.PathLike[str]],
    *,
    dry_run: bool = False,
) -> BatchOutcome:
    """Preflight an entire approved batch, then remove each exact identity."""
    roots = tuple(allowed_roots)
    persisted = _approved_session_batch(session, batch)
    preflights = tuple(_preflight_target(target, roots) for target in persisted.targets)
    issues = tuple(issue for result in preflights for issue in result.issues)
    issues += _state_precondition_issues(session, preflights, applying=True)
    has_critical = _has_severity(issues, Severity.CRITICAL)
    has_batch_error = _has_severity(issues, Severity.BATCH_ERROR)

    if dry_run or has_critical:
        return BatchOutcome(
            persisted.id,
            issues,
            dry_run=dry_run,
            suspended=has_batch_error,
        )
    if has_batch_error:
        _record_new_issues(session, issues)
        _suspend_mutable_targets(session, persisted)
        return BatchOutcome(persisted.id, issues, suspended=True)

    before = _free_space(roots, persisted)
    removed = 0
    runtime_issues: list[Issue] = []
    for result in preflights:
        status = session.status(result.target.id)
        if status == "verified":
            continue
        if result.absent:
            _record_new_issues(session, result.issues)
            if status == "approved":
                session.transition(result.target.id, "applied")
            verification_issue = _absence_issue(result.target, roots)
            if verification_issue is None:
                session.transition(result.target.id, "verified")
                continue
            runtime_issues.append(verification_issue)
            break

        assert result.identity is not None
        try:
            removed += remove_tree_exact(result.identity, roots)
        except PathSafetyError as error:
            runtime_issues.append(_issue_from_safety_error(result.target, error))
            break
        except PermissionError as error:
            runtime_issues.append(_permission_issue(result.target, error))
            break
        except OSError as error:
            runtime_issues.append(_os_issue(result.target, error))
            break

        session.transition(result.target.id, "applied")
        verification_issue = _absence_issue(result.target, roots)
        if verification_issue is None:
            session.transition(result.target.id, "verified")
        else:
            runtime_issues.append(verification_issue)
            break

    after = _free_space(roots, persisted)
    if runtime_issues:
        runtime = tuple(runtime_issues)
        if not _has_severity(runtime, Severity.CRITICAL):
            _record_new_issues(session, runtime)
            _suspend_mutable_targets(session, persisted)
        return BatchOutcome(
            persisted.id,
            issues + runtime,
            removed,
            before,
            after,
            suspended=True,
        )
    return BatchOutcome(persisted.id, issues, removed, before, after)


def verify_batch(
    session: Session,
    batch: Batch,
    allowed_roots: Iterable[str | os.PathLike[str]],
) -> BatchOutcome:
    """Explicitly verify absence; never remove a target."""
    roots = tuple(allowed_roots)
    persisted = _approved_session_batch(session, batch)
    preflights = tuple(_preflight_target(target, roots) for target in persisted.targets)
    issues = tuple(issue for result in preflights for issue in result.issues)
    issues += _state_precondition_issues(session, preflights, applying=False)
    has_critical = _has_severity(issues, Severity.CRITICAL)
    has_batch_error = _has_severity(issues, Severity.BATCH_ERROR)
    if has_critical:
        return BatchOutcome(persisted.id, issues, suspended=has_batch_error)
    if has_batch_error:
        _record_new_issues(session, issues)
        _suspend_mutable_targets(session, persisted)
        return BatchOutcome(persisted.id, issues, suspended=True)

    for result in preflights:
        status = session.status(result.target.id)
        if status == "verified":
            continue
        _record_new_issues(session, result.issues)
        if status == "approved":
            session.transition(result.target.id, "applied")
        session.transition(result.target.id, "verified")
    return BatchOutcome(persisted.id, issues)


def _preflight_target(
    target: Target, roots: tuple[str | os.PathLike[str], ...]
) -> _Preflight:
    location_issue = _location_issue(target, roots)
    if location_issue is not None:
        return _Preflight(target, issues=(location_issue,))
    try:
        os.lstat(target.path)
    except FileNotFoundError:
        return _Preflight(target, issues=(_absent_issue(target),))
    except PermissionError as error:
        return _Preflight(target, issues=(_permission_issue(target, error),))
    except OSError as error:
        return _Preflight(target, issues=(_os_issue(target, error),))
    try:
        identity = inspect_path(target.path, roots)
    except PathSafetyError as error:
        return _Preflight(target, issues=(_issue_from_safety_error(target, error),))
    if identity.canonical != target.path or identity.kind != target.kind:
        return _Preflight(target, issues=(_critical_location_issue(target),))
    if identity.fingerprint != target.fingerprint:
        return _Preflight(
            target,
            issues=(
                Issue(
                    "executor.fingerprint-changed",
                    Severity.BATCH_ERROR,
                    f"Target changed after approval: {target.path}",
                    target.id,
                ),
            ),
        )
    if _target_in_use(identity):
        return _Preflight(
            target,
            issues=(
                Issue(
                    "executor.target-in-use",
                    Severity.BATCH_ERROR,
                    f"Target is in use: {target.path}",
                    target.id,
                ),
            ),
        )
    return _Preflight(target, identity)


def _approved_session_batch(session: Session, supplied: Batch) -> Batch:
    if not isinstance(supplied, Batch):
        raise TypeError("batch must be a Batch")
    matches = tuple(
        batch for batch in session.read_manifest().batches if batch.id == supplied.id
    )
    if len(matches) != 1 or matches[0] != supplied:
        raise ValueError("batch must exactly match one named session manifest batch")
    persisted = matches[0]
    for target in persisted.targets:
        status = session.status(target.id)
        if status not in {"approved", "applied", "verified"}:
            raise ValueError(
                f"batch target is not approved or resumable: {target.id}: {status}"
            )
    return persisted


def _state_precondition_issues(
    session: Session, preflights: tuple[_Preflight, ...], *, applying: bool
) -> tuple[Issue, ...]:
    issues: list[Issue] = []
    for result in preflights:
        status = session.status(result.target.id)
        if result.absent or status == "verified":
            continue
        if status == "applied" or not applying:
            issues.append(
                Issue(
                    "executor.postcondition-failed",
                    Severity.BATCH_ERROR,
                    f"Target remains present during verification: {result.target.path}",
                    result.target.id,
                )
            )
    return tuple(issues)


def _location_issue(
    target: Target, roots: tuple[str | os.PathLike[str], ...]
) -> Issue | None:
    try:
        candidate = Path(target.path)
        if not candidate.is_absolute() or ".." in candidate.parts:
            return _critical_location_issue(target)
        canonical_roots = tuple(_canonical_root(root) for root in roots)
        if not canonical_roots:
            return _critical_location_issue(target)
        if not any(_strictly_below(candidate, root) for root in canonical_roots):
            return _critical_location_issue(target)
        current = Path(candidate.anchor)
        for part in candidate.parts[1:]:
            current /= part
            try:
                current_stat = current.lstat()
            except FileNotFoundError:
                break
            if stat.S_ISLNK(current_stat.st_mode):
                return _critical_location_issue(target)
    except PermissionError as error:
        return _permission_issue(target, error)
    except OSError as error:
        return _os_issue(target, error)
    except (TypeError, ValueError):
        return _critical_location_issue(target)
    return None


def _canonical_root(root: str | os.PathLike[str]) -> Path:
    path = Path(root)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("allowed root must be absolute and canonical")
    current = Path(path.anchor)
    for part in path.parts[1:]:
        current /= part
        if stat.S_ISLNK(current.lstat().st_mode):
            raise ValueError("allowed root must not contain symlinks")
    canonical = path.resolve(strict=True)
    if not canonical.is_dir():
        raise ValueError("allowed root must be a directory")
    return canonical


def _strictly_below(path: Path, root: Path) -> bool:
    try:
        return path.relative_to(root) != Path(".")
    except ValueError:
        return False


def _absence_issue(
    target: Target, roots: tuple[str | os.PathLike[str], ...]
) -> Issue | None:
    location_issue = _location_issue(target, roots)
    if location_issue is not None:
        return location_issue
    try:
        os.lstat(target.path)
    except FileNotFoundError:
        return None
    except PermissionError as error:
        return _permission_issue(target, error)
    except OSError as error:
        return _os_issue(target, error)
    return Issue(
        "executor.postcondition-failed",
        Severity.BATCH_ERROR,
        f"Target remains present after apply: {target.path}",
        target.id,
    )


def _target_in_use(identity: PathIdentity) -> bool:
    """Detect a cooperating process holding an advisory lock without mutation."""
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if identity.kind == "directory" and hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    try:
        descriptor = os.open(identity.canonical, flags)
    except OSError:
        # Path inspection already classified accessibility and identity. Failure
        # here is not positive evidence that another process owns the target.
        return False
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        except OSError as error:
            return error.errno in {errno.EAGAIN, errno.EACCES, errno.EBUSY}
        fcntl.flock(descriptor, fcntl.LOCK_UN)
        return False
    finally:
        os.close(descriptor)


def _issue_from_safety_error(target: Target, error: PathSafetyError) -> Issue:
    cause = error.__cause__
    if isinstance(cause, FileNotFoundError):
        return _absent_issue(target)
    if isinstance(cause, PermissionError):
        return _permission_issue(target, cause)
    if isinstance(cause, OSError) and cause.errno in {errno.EBUSY, errno.ETXTBSY}:
        return _in_use_issue(target, cause)
    text = str(error).casefold()
    if "changed since inspection" in text or "changed while opening" in text:
        return Issue(
            "executor.fingerprint-changed",
            Severity.BATCH_ERROR,
            f"Target changed during apply: {target.path}",
            target.id,
        )
    return _critical_location_issue(target)


def _os_issue(target: Target, error: OSError) -> Issue:
    if error.errno in {errno.EBUSY, errno.ETXTBSY}:
        return _in_use_issue(target, error)
    if error.errno in {errno.EACCES, errno.EPERM}:
        return _permission_issue(target, error)
    return Issue(
        "executor.preflight-failed",
        Severity.BATCH_ERROR,
        f"Cannot safely inspect target: {target.path}: {error}",
        target.id,
    )


def _absent_issue(target: Target) -> Issue:
    return Issue(
        "executor.target-absent",
        Severity.INFORMATIONAL,
        f"Target is already absent: {target.path}",
        target.id,
    )


def _critical_location_issue(target: Target) -> Issue:
    return Issue(
        "executor.symlink-or-outside",
        Severity.CRITICAL,
        f"Target is a symlink, noncanonical, or outside allowed roots: {target.path}",
        target.id,
    )


def _permission_issue(target: Target, error: BaseException) -> Issue:
    return Issue(
        "executor.permission-denied",
        Severity.BATCH_ERROR,
        f"Permission denied for target: {target.path}: {error}",
        target.id,
    )


def _in_use_issue(target: Target, error: BaseException) -> Issue:
    return Issue(
        "executor.target-in-use",
        Severity.BATCH_ERROR,
        f"Target is in use: {target.path}: {error}",
        target.id,
    )


def _has_severity(issues: tuple[Issue, ...], severity: Severity) -> bool:
    return any(issue.severity is severity for issue in issues)


def _suspend_mutable_targets(session: Session, batch: Batch) -> None:
    mutable = tuple(
        target.id
        for target in batch.targets
        if session.status(target.id) in {"approved", "applied"}
    )
    if mutable:
        session.transition_batch(mutable, "suspended")


def _record_new_issues(session: Session, issues: tuple[Issue, ...]) -> None:
    for issue in issues:
        if issue.severity is not Severity.CRITICAL:
            session.add_issue(issue)


def _free_space(
    roots: tuple[str | os.PathLike[str], ...], batch: Batch
) -> int:
    measurement_path: str | os.PathLike[str]
    if roots:
        measurement_path = roots[0]
    elif batch.targets:
        measurement_path = Path(batch.targets[0].path).parent
    else:
        raise ValueError("cannot measure an empty batch without an allowed root")
    return shutil.disk_usage(measurement_path).free
