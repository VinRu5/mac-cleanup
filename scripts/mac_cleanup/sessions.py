"""Durable, atomic session artifacts and target lifecycle state."""

from __future__ import annotations

from contextlib import contextmanager
import copy
from datetime import datetime, timezone
import fcntl
import hashlib
import json
import os
from pathlib import Path
import tempfile
import threading
from typing import Iterator, Mapping, Sequence

from .jsonio import atomic_write_json, canonical_bytes, read_json
from .models import Issue, Manifest, Severity, TargetStatus


SCHEMA_VERSION = 1

ALLOWED_TRANSITIONS = {
    "pending": {"approved", "skipped", "suspended"},
    "approved": {"applied", "skipped", "suspended", "failed"},
    "applied": {"verified", "suspended", "failed"},
    "suspended": {"pending", "skipped"},
    "skipped": set(),
    "verified": set(),
    "failed": set(),
}


class _LocalSessionLock:
    """Process-local reentrancy state layered over an inter-process flock."""

    def __init__(self) -> None:
        self.pid = os.getpid()
        self.gate = threading.RLock()
        self.depth = 0
        self.file_descriptor: int | None = None


_LOCAL_LOCKS_GUARD = threading.Lock()
_LOCAL_LOCKS: dict[str, _LocalSessionLock] = {}


class InvalidTransition(ValueError):
    """Raised when a target lifecycle transition is not explicitly allowed."""


class SessionConsistencyError(ValueError):
    """Raised when session artifacts cannot be reconciled safely."""


def _local_session_lock(path: Path) -> _LocalSessionLock:
    key = str(path.resolve(strict=False))
    with _LOCAL_LOCKS_GUARD:
        local = _LOCAL_LOCKS.get(key)
        if local is None or local.pid != os.getpid():
            local = _LocalSessionLock()
            _LOCAL_LOCKS[key] = local
        return local


class Session:
    """Own a session directory whose state file is the recovery authority."""

    def __init__(self, path: Path, state: dict[str, object]) -> None:
        self.path = path
        self._state = state

    @classmethod
    def create(cls, path: str | os.PathLike[str]) -> "Session":
        """Create a fresh session without treating an existing state as resumable."""
        directory = Path(path)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        os.chmod(directory, 0o700)
        state_path = directory / "state.json"
        if state_path.exists():
            raise FileExistsError(f"session state already exists: {state_path}")
        state: dict[str, object] = {
            "schema_version": SCHEMA_VERSION,
            "created_at": _timestamp(),
            "critical_stop": None,
            "events": [],
            "issues": [],
            "manifest": None,
            "targets": {},
        }
        atomic_write_json(state_path, state)
        session = cls(directory, state)
        session._ensure_lock_file()
        return session

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> "Session":
        """Load a persisted session; a missing state is never considered success."""
        directory = Path(path)
        state = read_json(directory / "state.json")
        _validate_state(state)
        session = cls(directory, state)
        with session.operation_lock():
            session._reconcile_manifest()
        return session

    @property
    def inventory_path(self) -> Path:
        return self.path / "inventory.json"

    @property
    def policy_path(self) -> Path:
        return self.path / "policy.json"

    @property
    def manifest_path(self) -> Path:
        return self.path / "manifest.json"

    @property
    def state_path(self) -> Path:
        return self.path / "state.json"

    @property
    def lock_path(self) -> Path:
        return self.path / ".session.lock"

    @property
    def report_path(self) -> Path:
        return self.path / "report.md"

    @property
    def state(self) -> dict[str, object]:
        """Return a copy so callers cannot mutate durable state accidentally."""
        with self.operation_lock():
            return copy.deepcopy(self._state)

    @contextmanager
    def operation_lock(self) -> Iterator[None]:
        """Serialize and refresh a complete session operation across processes."""
        local = _local_session_lock(self.lock_path)
        local.gate.acquire()
        outermost = local.depth == 0
        try:
            if outermost:
                descriptor = os.open(
                    self.lock_path,
                    os.O_CREAT | os.O_RDWR,
                    0o600,
                )
                os.fchmod(descriptor, 0o600)
                fcntl.flock(descriptor, fcntl.LOCK_EX)
                local.file_descriptor = descriptor
            local.depth += 1
            self._reload_state_locked()
            yield
        finally:
            if local.depth > 0:
                local.depth -= 1
            if outermost and local.file_descriptor is not None:
                descriptor = local.file_descriptor
                local.file_descriptor = None
                fcntl.flock(descriptor, fcntl.LOCK_UN)
                os.close(descriptor)
            local.gate.release()

    def write_inventory(self, inventory: Mapping[str, object]) -> None:
        atomic_write_json(self.inventory_path, _object(inventory, "inventory"))

    def read_inventory(self) -> dict[str, object]:
        return read_json(self.inventory_path)

    def write_policy(self, policy: Mapping[str, object]) -> None:
        atomic_write_json(self.policy_path, _object(policy, "policy"))

    def read_policy(self) -> dict[str, object]:
        return read_json(self.policy_path)

    def write_manifest(self, manifest: Manifest | Mapping[str, object]) -> None:
        """Persist an immutable manifest and register its target lifecycle states."""
        with self.operation_lock():
            self._write_manifest_locked(manifest)

    def _write_manifest_locked(
        self, manifest: Manifest | Mapping[str, object]
    ) -> None:
        value = manifest.to_dict() if isinstance(manifest, Manifest) else _object(manifest, "manifest")
        value = _strict_manifest_value(value)
        target_statuses = _target_statuses(value)
        record = _manifest_record(value, target_statuses)
        current_targets = self._targets()
        existing = _state_manifest_record(self._state)
        if existing is None:
            if current_targets:
                raise SessionConsistencyError("state targets exist without a manifest record")
            next_state = copy.deepcopy(self._state)
            next_state["manifest"] = record
            next_state["targets"] = target_statuses
            self._persist_state(next_state)
        elif existing["digest"] != record["digest"]:
            raise ValueError("manifest is immutable once written to a session")
        elif set(current_targets) != set(target_statuses):
            raise SessionConsistencyError("state targets do not match the session manifest")

        if self.manifest_path.exists():
            self._validate_manifest_artifact_bytes(record)
            return
        atomic_write_json(self.manifest_path, record["value"])

    def read_manifest(self) -> Manifest:
        """Read only the exact raw manifest bytes recorded in durable state."""
        with self.operation_lock():
            return self._read_manifest_locked()

    def _read_manifest_locked(self) -> Manifest:
        record = _state_manifest_record(self._state)
        if record is not None:
            self._validate_manifest_artifact_bytes(record)
            value = record["value"]
            assert isinstance(value, Mapping)
            return Manifest.from_dict(value)
        return Manifest.from_dict(read_json(self.manifest_path))

    def write_report(self, report: str) -> None:
        if not isinstance(report, str):
            raise TypeError("report must be text")
        _atomic_write_text(self.report_path, report)

    def add_issue(self, issue: Issue | Mapping[str, object]) -> None:
        with self.operation_lock():
            value = issue.to_dict() if isinstance(issue, Issue) else _object(issue, "issue")
            next_state = copy.deepcopy(self._state)
            issues = next_state["issues"]
            assert isinstance(issues, list)
            issues.append({"at": _timestamp(), **value})
            self._persist_state(next_state)

    def critical_issue(self) -> Issue | None:
        """Return the durable global-stop cause, if one has been latched."""
        with self.operation_lock():
            return self._critical_issue_locked()

    def _critical_issue_locked(self) -> Issue | None:
        value = self._state.get("critical_stop")
        if value is None:
            return None
        assert isinstance(value, Mapping)
        return Issue.from_dict(value)

    def latch_critical(self, issue: Issue) -> None:
        """Atomically persist the first critical issue as a global stop."""
        if not isinstance(issue, Issue):
            raise TypeError("critical stop must be an Issue")
        if issue.severity is not Severity.CRITICAL:
            raise ValueError("critical stop issue must have critical severity")
        with self.operation_lock():
            if self._critical_issue_locked() is not None:
                return
            record = {"at": _timestamp(), **issue.to_dict()}
            next_state = copy.deepcopy(self._state)
            next_state["critical_stop"] = record
            issues = next_state["issues"]
            assert isinstance(issues, list)
            issues.append(record.copy())
            self._persist_state(next_state)

    def status(self, target_id: str) -> str:
        with self.operation_lock():
            return self._status_locked(target_id)

    def _status_locked(self, target_id: str) -> str:
        target = self._targets().get(target_id)
        if target is None:
            raise KeyError(f"target is absent from session manifest: {target_id}")
        return target

    def transition(self, target_id: str, destination: str | TargetStatus) -> None:
        """Atomically record one explicit target-state change."""
        self.transition_batch((target_id,), destination)

    def transition_batch(
        self, target_ids: Sequence[str], destination: str | TargetStatus
    ) -> None:
        """Atomically transition every supplied target after validating all of them."""
        with self.operation_lock():
            self._transition_batch_locked(target_ids, destination)

    def _transition_batch_locked(
        self, target_ids: Sequence[str], destination: str | TargetStatus
    ) -> None:
        identifiers = tuple(target_ids)
        if not identifiers:
            raise ValueError("batch transition requires at least one target")
        if len(set(identifiers)) != len(identifiers):
            raise ValueError("batch transition target ids must be unique")
        next_status = TargetStatus(destination).value
        current_statuses: list[tuple[str, str]] = []
        for target_id in identifiers:
            current_status = self._status_locked(target_id)
            if next_status not in ALLOWED_TRANSITIONS[current_status]:
                raise InvalidTransition(
                    f"cannot transition {target_id}: {current_status} -> {next_status}"
                )
            current_statuses.append((target_id, current_status))

        next_state = copy.deepcopy(self._state)
        targets = next_state["targets"]
        events = next_state["events"]
        assert isinstance(targets, dict)
        assert isinstance(events, list)
        timestamp = _timestamp()
        for target_id, current_status in current_statuses:
            targets[target_id] = next_status
            events.append(
                {
                    "at": timestamp,
                    "from": current_status,
                    "target_id": target_id,
                    "to": next_status,
                }
            )
        self._persist_state(next_state)

    def _targets(self) -> dict[str, str]:
        targets = self._state["targets"]
        assert isinstance(targets, dict)
        return targets  # type: ignore[return-value]

    def _ensure_lock_file(self) -> None:
        descriptor = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, 0o600)
        try:
            os.fchmod(descriptor, 0o600)
        finally:
            os.close(descriptor)

    def _reload_state_locked(self) -> None:
        state = read_json(self.state_path)
        _validate_state(state)
        self._state = state

    def _persist_state(self, state: dict[str, object]) -> None:
        _validate_state(state)
        atomic_write_json(self.state_path, state)
        self._state = state

    def _reconcile_manifest(self) -> None:
        """Repair a missing manifest artifact only from state, never by inference."""
        record = _state_manifest_record(self._state)
        current_targets = self._targets()
        if record is None:
            if not self.manifest_path.exists():
                if current_targets:
                    raise SessionConsistencyError("state targets exist without a manifest artifact")
                return
            artifact = read_json(self.manifest_path)
            statuses = _target_statuses(artifact)
            if current_targets and set(current_targets) != set(statuses):
                raise SessionConsistencyError("legacy state targets do not match manifest artifact")
            next_state = copy.deepcopy(self._state)
            next_state["manifest"] = _manifest_record(artifact, statuses)
            if not current_targets:
                next_state["targets"] = statuses
            self._persist_state(next_state)
            return

        if set(current_targets) != set(record["target_ids"]):
            raise SessionConsistencyError("state target ids do not match manifest record")
        if self.manifest_path.exists():
            self._validate_manifest_artifact_bytes(record)
            return
        atomic_write_json(self.manifest_path, record["value"])

    def _validate_manifest_artifact_bytes(self, record: Mapping[str, object]) -> None:
        """Reject every artifact variation before JSON parsing can normalize it."""
        digest = record.get("digest")
        value = record.get("value")
        if not isinstance(digest, str) or not isinstance(value, Mapping):
            raise SessionConsistencyError("state manifest record is malformed")
        expected = canonical_bytes(value)
        actual = self.manifest_path.read_bytes()
        if hashlib.sha256(actual).hexdigest() != digest or actual != expected:
            raise SessionConsistencyError("manifest artifact differs from durable state")


def _object(value: Mapping[str, object], label: str) -> dict[str, object]:
    if not isinstance(value, Mapping):
        raise TypeError(f"{label} must be an object")
    return dict(value)


def _require_schema(value: Mapping[str, object], label: str) -> None:
    if value.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"{label} schema_version must be {SCHEMA_VERSION}")


def _strict_manifest_value(value: Mapping[str, object]) -> dict[str, object]:
    """Accept only the complete canonical manifest schema at persistence ingress."""
    _require_schema(value, "manifest")
    original = _canonical_object(value)
    expected = Manifest.from_dict(original).to_dict()
    if canonical_bytes(original) != canonical_bytes(expected):
        raise ValueError("manifest must match the complete canonical schema")
    return expected


def _target_statuses(manifest: Mapping[str, object]) -> dict[str, str]:
    targets: dict[str, str] = {}
    batches = manifest.get("batches")
    if not isinstance(batches, list):
        raise ValueError("manifest batches must be a list")
    for batch in batches:
        if not isinstance(batch, Mapping):
            raise ValueError("manifest batch must be an object")
        members = batch.get("targets")
        if not isinstance(members, list):
            raise ValueError("manifest targets must be a list")
        for member in members:
            if not isinstance(member, Mapping) or not isinstance(member.get("id"), str):
                raise ValueError("manifest target must have a text id")
            target_id = member["id"]
            if target_id in targets:
                raise ValueError(f"manifest target appears more than once: {target_id}")
            targets[target_id] = TargetStatus(member.get("status", "pending")).value
    return targets


def _manifest_digest(value: Mapping[str, object]) -> str:
    return hashlib.sha256(canonical_bytes(value)).hexdigest()


def _manifest_record(
    value: Mapping[str, object], target_statuses: Mapping[str, str]
) -> dict[str, object]:
    canonical_value = _canonical_object(value)
    return {
        "digest": _manifest_digest(canonical_value),
        "target_ids": sorted(target_statuses),
        "value": canonical_value,
    }


def _state_manifest_record(state: Mapping[str, object]) -> dict[str, object] | None:
    record = state.get("manifest")
    if record is None:
        return None
    if not isinstance(record, Mapping):
        raise ValueError("state manifest must be an object or null")
    digest = record.get("digest")
    target_ids = record.get("target_ids")
    value = record.get("value")
    if not isinstance(digest, str) or not isinstance(target_ids, list) or not isinstance(value, Mapping):
        raise ValueError("state manifest record is malformed")
    if not all(isinstance(target_id, str) for target_id in target_ids):
        raise ValueError("state manifest target ids must be text")
    statuses = _target_statuses(value)
    if target_ids != sorted(statuses) or digest != _manifest_digest(value):
        raise ValueError("state manifest record does not match its payload")
    return {"digest": digest, "target_ids": target_ids, "value": _canonical_object(value)}


def _canonical_object(value: Mapping[str, object]) -> dict[str, object]:
    copied = json.loads(canonical_bytes(value).decode("utf-8"))
    assert isinstance(copied, dict)
    return copied


def _validate_state(state: Mapping[str, object]) -> None:
    _require_schema(state, "state")
    for key, expected in (("created_at", str), ("events", list), ("issues", list), ("targets", dict)):
        if not isinstance(state.get(key), expected):
            raise ValueError(f"state {key} must be a {expected.__name__}")
    targets = state["targets"]
    assert isinstance(targets, dict)
    for target_id, status in targets.items():
        if not isinstance(target_id, str):
            raise ValueError("state target ids must be text")
        TargetStatus(status)
    record = _state_manifest_record(state)
    if record is not None and set(targets) != set(record["target_ids"]):
        raise ValueError("state target ids do not match manifest record")
    critical_stop = state.get("critical_stop")
    if critical_stop is not None:
        if not isinstance(critical_stop, Mapping):
            raise ValueError("state critical_stop must be an object or null")
        critical_issue = Issue.from_dict(critical_stop)
        if critical_issue.severity is not Severity.CRITICAL:
            raise ValueError("state critical_stop must contain a critical issue")


def _timestamp() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds").replace("+00:00", "Z")


def _atomic_write_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(value)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise
