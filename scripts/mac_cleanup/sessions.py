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
import re
import stat
import tempfile
import threading
from typing import Iterator, Mapping, Sequence
import uuid

from .jsonio import atomic_write_json, canonical_bytes, read_json
from .models import Issue, Manifest, Severity, TargetStatus


SCHEMA_VERSION = 1
_LOCK_ACQUIRE_ATTEMPTS = 8

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
_LOCAL_LOCKS_PID = os.getpid()


class InvalidTransition(ValueError):
    """Raised when a target lifecycle transition is not explicitly allowed."""


class SessionConsistencyError(ValueError):
    """Raised when session artifacts cannot be reconciled safely."""


def _close_inherited_lock_descriptor(local: _LocalSessionLock) -> None:
    """Drop a child's inherited descriptor without unlocking the parent."""
    if local.pid == os.getpid():
        return
    descriptor = local.file_descriptor
    local.file_descriptor = None
    local.depth = 0
    if descriptor is not None:
        try:
            os.close(descriptor)
        except OSError:
            pass


def _reset_local_locks_after_fork() -> None:
    """Discard synchronization state and lock descriptors inherited by a child."""
    global _LOCAL_LOCKS, _LOCAL_LOCKS_GUARD, _LOCAL_LOCKS_PID
    for local in _LOCAL_LOCKS.values():
        _close_inherited_lock_descriptor(local)
    _LOCAL_LOCKS = {}
    _LOCAL_LOCKS_GUARD = threading.Lock()
    _LOCAL_LOCKS_PID = os.getpid()


def _local_session_lock(path: Path) -> _LocalSessionLock:
    global _LOCAL_LOCKS_PID
    if _LOCAL_LOCKS_PID != os.getpid():
        _reset_local_locks_after_fork()
    key = str(path)
    with _LOCAL_LOCKS_GUARD:
        local = _LOCAL_LOCKS.get(key)
        if local is not None and local.pid != os.getpid():
            _close_inherited_lock_descriptor(local)
            local = None
        if local is None:
            local = _LocalSessionLock()
            _LOCAL_LOCKS[key] = local
        return local


def _directory_open_flags() -> int:
    flags = os.O_RDONLY
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _canonical_session_path(path: str | os.PathLike[str]) -> Path:
    directory = Path(path)
    if not directory.is_absolute() or ".." in directory.parts:
        raise ValueError("session path must be absolute and canonical")
    try:
        canonical = directory.resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise ValueError("session path cannot be resolved safely") from error
    if canonical != directory:
        raise ValueError("session path must not contain symlinks or aliases")
    return directory


def _open_session_directory(
    path: str | os.PathLike[str], *, create: bool
) -> tuple[Path, int, tuple[int, int]]:
    """Open a canonical session directory without following path components."""
    directory = _canonical_session_path(path)
    flags = _directory_open_flags()
    descriptor = os.open(directory.anchor, flags)
    created_final = False
    try:
        parts = directory.parts[1:]
        for index, part in enumerate(parts):
            created = False
            try:
                child = os.open(part, flags, dir_fd=descriptor)
            except FileNotFoundError:
                if not create:
                    raise
                os.mkdir(part, 0o700, dir_fd=descriptor)
                created = True
                child = os.open(part, flags, dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
            if index == len(parts) - 1:
                created_final = created

        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.getuid()
            or stat.S_IMODE(metadata.st_mode) != 0o700
        ):
            raise SessionConsistencyError(
                "session directory must be a current-user directory with mode 0700"
            )
        named = os.stat(directory, follow_symlinks=False)
        identity = (metadata.st_dev, metadata.st_ino)
        if (named.st_dev, named.st_ino) != identity:
            raise SessionConsistencyError("session directory identity changed")
        if created_final and stat.S_IMODE(metadata.st_mode) != 0o700:
            raise SessionConsistencyError("new session directory mode is unsafe")
        return directory, descriptor, identity
    except BaseException:
        os.close(descriptor)
        raise


def _open_bound_session_directory(
    path: Path, expected_identity: tuple[int, int]
) -> int:
    directory, descriptor, identity = _open_session_directory(path, create=False)
    del directory
    if identity != expected_identity:
        os.close(descriptor)
        raise SessionConsistencyError("session directory was replaced")
    return descriptor


def _lock_open_flags() -> int:
    flags = os.O_RDWR
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    if hasattr(os, "O_CLOEXEC"):
        flags |= os.O_CLOEXEC
    return flags


def _open_lock_file(directory_descriptor: int, *, create: bool) -> int:
    """Open the exact regular lock entry without modifying a preexisting object."""
    flags = _lock_open_flags()
    created = False
    if create:
        try:
            descriptor = os.open(
                ".session.lock",
                flags | os.O_CREAT | os.O_EXCL,
                0o600,
                dir_fd=directory_descriptor,
            )
            created = True
        except FileExistsError:
            descriptor = os.open(
                ".session.lock", flags, dir_fd=directory_descriptor
            )
    else:
        descriptor = os.open(".session.lock", flags, dir_fd=directory_descriptor)
    try:
        if created:
            os.fchmod(descriptor, 0o600)
        _validate_lock_descriptor(descriptor, directory_descriptor)
        named = os.stat(
            ".session.lock",
            dir_fd=directory_descriptor,
            follow_symlinks=False,
        )
        locked = os.fstat(descriptor)
        if (named.st_dev, named.st_ino) != (locked.st_dev, locked.st_ino):
            raise SessionConsistencyError("session lock metadata is unsafe")
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _validate_lock_descriptor(
    descriptor: int, directory_descriptor: int
) -> None:
    locked = os.fstat(descriptor)
    parent = os.fstat(directory_descriptor)
    if (
        not stat.S_ISREG(locked.st_mode)
        or locked.st_uid != os.getuid()
        or locked.st_gid != parent.st_gid
        or locked.st_dev != parent.st_dev
        or locked.st_nlink != 1
        or stat.S_IMODE(locked.st_mode) != 0o600
    ):
        raise SessionConsistencyError("session lock metadata is unsafe")


def _same_lock_inode(
    path: Path,
    descriptor: int,
    directory_identity: tuple[int, int],
) -> bool:
    try:
        directory_descriptor = _open_bound_session_directory(
            path.parent, directory_identity
        )
        try:
            current = os.stat(
                path.name,
                dir_fd=directory_descriptor,
                follow_symlinks=False,
            )
            locked = os.fstat(descriptor)
            if (current.st_dev, current.st_ino) != (
                locked.st_dev,
                locked.st_ino,
            ):
                return False
            _validate_lock_descriptor(descriptor, directory_descriptor)
        finally:
            os.close(directory_descriptor)
    except OSError:
        return False
    return True


def _acquire_stable_lock(
    path: Path, directory_identity: tuple[int, int]
) -> int:
    """Lock the inode currently named by ``path``, retrying replacements."""
    for _ in range(_LOCK_ACQUIRE_ATTEMPTS):
        directory_descriptor = _open_bound_session_directory(
            path.parent, directory_identity
        )
        try:
            descriptor = _open_lock_file(directory_descriptor, create=True)
        finally:
            os.close(directory_descriptor)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            if _same_lock_inode(path, descriptor, directory_identity):
                return descriptor
            fcntl.flock(descriptor, fcntl.LOCK_UN)
        except BaseException:
            os.close(descriptor)
            raise
        os.close(descriptor)
    raise SessionConsistencyError("session lock pathname did not stabilize")


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_reset_local_locks_after_fork)


class Session:
    """Own a session directory whose state file is the recovery authority."""

    def __init__(
        self,
        path: Path,
        state: dict[str, object],
        directory_identity: tuple[int, int],
    ) -> None:
        self.path = path
        self._state = state
        self._directory_identity = directory_identity

    @classmethod
    def create(cls, path: str | os.PathLike[str]) -> "Session":
        """Create a fresh session without treating an existing state as resumable."""
        directory, directory_descriptor, identity = _open_session_directory(
            path, create=True
        )
        try:
            try:
                os.stat(
                    "state.json",
                    dir_fd=directory_descriptor,
                    follow_symlinks=False,
                )
            except FileNotFoundError:
                pass
            else:
                raise FileExistsError(
                    f"session state already exists: {directory / 'state.json'}"
                )
            lock_descriptor = _open_lock_file(directory_descriptor, create=True)
            os.close(lock_descriptor)
            state: dict[str, object] = {
                "schema_version": SCHEMA_VERSION,
                "created_at": _timestamp(),
                "admin_scripts": {},
                "critical_stop": None,
                "events": [],
                "issues": [],
                "manifest": None,
                "mutation_intent": None,
                "targets": {},
            }
            named = os.stat(directory, follow_symlinks=False)
            if (named.st_dev, named.st_ino) != identity:
                raise SessionConsistencyError("session directory changed before state write")
            atomic_write_json(directory / "state.json", state)
        finally:
            os.close(directory_descriptor)
        return cls(directory, state, identity)

    @classmethod
    def load(cls, path: str | os.PathLike[str]) -> "Session":
        """Load a persisted session; a missing state is never considered success."""
        directory, descriptor, identity = _open_session_directory(
            path, create=False
        )
        try:
            state = read_json(directory / "state.json")
            _validate_state(state)
        finally:
            os.close(descriptor)
        session = cls(directory, state, identity)
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
                descriptor = _acquire_stable_lock(
                    self.lock_path, self._directory_identity
                )
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

    def assert_operation_lock_current(self) -> None:
        """Fail closed if this operation no longer owns the named lock inode."""
        local = _local_session_lock(self.lock_path)
        if (
            local.depth <= 0
            or local.file_descriptor is None
            or not _same_lock_inode(
                self.lock_path,
                local.file_descriptor,
                self._directory_identity,
            )
        ):
            raise SessionConsistencyError("session lock was replaced during operation")

    def write_inventory(self, inventory: Mapping[str, object]) -> None:
        self._assert_session_directory_current()
        atomic_write_json(self.inventory_path, _object(inventory, "inventory"))

    def read_inventory(self) -> dict[str, object]:
        return read_json(self.inventory_path)

    def write_policy(self, policy: Mapping[str, object]) -> None:
        self._assert_session_directory_current()
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
        self._assert_session_directory_current()
        _atomic_write_text(self.report_path, report)

    def bind_admin_script(
        self, batch_id: str, binding: Mapping[str, object]
    ) -> None:
        """Persist one immutable administrative-script binding under the session lock."""
        if not isinstance(batch_id, str) or not batch_id:
            raise ValueError("administrative batch id must be non-empty text")
        value = _canonical_object(_object(binding, "administrative script binding"))
        with self.operation_lock():
            current = self._state.get("admin_scripts", {})
            if not isinstance(current, Mapping):
                raise SessionConsistencyError("state admin_scripts is malformed")
            existing = current.get(batch_id)
            if existing is not None:
                if existing != value:
                    raise ValueError(
                        "administrative script binding is immutable once recorded"
                    )
                return
            next_state = copy.deepcopy(self._state)
            scripts = next_state.setdefault("admin_scripts", {})
            assert isinstance(scripts, dict)
            scripts[batch_id] = value
            self._persist_state(next_state)

    def admin_script_binding(self, batch_id: str) -> dict[str, object] | None:
        """Return a copy of the immutable administrative binding for a batch."""
        with self.operation_lock():
            scripts = self._state.get("admin_scripts", {})
            if not isinstance(scripts, Mapping):
                raise SessionConsistencyError("state admin_scripts is malformed")
            value = scripts.get(batch_id)
            if value is None:
                return None
            if not isinstance(value, Mapping):
                raise SessionConsistencyError(
                    "state administrative script binding is malformed"
                )
            return copy.deepcopy(dict(value))

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

    def mutation_intent(self) -> dict[str, object] | None:
        """Return the authoritative unresolved mutation/accounting intent."""
        with self.operation_lock():
            value = self._state.get("mutation_intent")
            if value is None:
                return None
            assert isinstance(value, Mapping)
            return copy.deepcopy(dict(value))

    def begin_mutation_intent(
        self, *, operation: str, batch_id: str, target_id: str
    ) -> dict[str, object]:
        """Persist the fail-safe authority immediately before cleanup mutation."""
        if operation != "apply":
            raise ValueError("mutation intent operation must be apply")
        if not isinstance(batch_id, str) or not batch_id:
            raise ValueError("mutation intent batch id must be non-empty text")
        if not isinstance(target_id, str) or not target_id:
            raise ValueError("mutation intent target id must be non-empty text")
        with self.operation_lock():
            if self._state.get("mutation_intent") is not None:
                raise SessionConsistencyError(
                    "session has an unresolved mutation intent"
                )
            manifest = self._read_manifest_locked()
            matches = tuple(batch for batch in manifest.batches if batch.id == batch_id)
            if len(matches) != 1 or target_id not in {
                target.id for target in matches[0].targets
            }:
                raise ValueError("mutation intent must name a manifest batch target")
            if self._status_locked(target_id) != "approved":
                raise ValueError("mutation intent target must be approved")
            intent: dict[str, object] = {
                "batch_id": batch_id,
                "created_at": _timestamp(),
                "operation": operation,
                "operation_id": uuid.uuid4().hex,
                "schema_version": SCHEMA_VERSION,
                "target_id": target_id,
            }
            _validate_mutation_intent(intent)
            next_state = copy.deepcopy(self._state)
            next_state["mutation_intent"] = intent
            self._persist_state(next_state)
            return copy.deepcopy(intent)

    def advance_mutation_intent(
        self, operation_id: str, target_id: str
    ) -> dict[str, object]:
        """Checkpoint the next exact target before its deletion begins."""
        with self.operation_lock():
            current = self._mutation_intent_for_operation(operation_id)
            manifest = self._read_manifest_locked()
            batch_id = current["batch_id"]
            matches = tuple(batch for batch in manifest.batches if batch.id == batch_id)
            if len(matches) != 1 or target_id not in {
                target.id for target in matches[0].targets
            }:
                raise ValueError("mutation intent must name a manifest batch target")
            if self._status_locked(target_id) != "approved":
                raise ValueError("mutation intent target must be approved")
            next_intent = copy.deepcopy(current)
            next_intent["target_id"] = target_id
            _validate_mutation_intent(next_intent)
            next_state = copy.deepcopy(self._state)
            next_state["mutation_intent"] = next_intent
            self._persist_state(next_state)
            return copy.deepcopy(next_intent)

    def clear_mutation_intent(self, operation_id: str) -> None:
        """Clear only the exact intent whose accounting was durably published."""
        with self.operation_lock():
            self._mutation_intent_for_operation(operation_id)
            next_state = copy.deepcopy(self._state)
            next_state["mutation_intent"] = None
            self._persist_state(next_state)

    def _mutation_intent_for_operation(
        self, operation_id: str
    ) -> dict[str, object]:
        value = self._state.get("mutation_intent")
        if not isinstance(value, Mapping):
            raise ValueError("session has no unresolved mutation intent")
        intent = dict(value)
        _validate_mutation_intent(intent)
        if intent["operation_id"] != operation_id:
            raise ValueError("mutation intent operation id changed")
        return intent

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
        directory_descriptor = _open_bound_session_directory(
            self.path, self._directory_identity
        )
        try:
            descriptor = _open_lock_file(directory_descriptor, create=True)
            os.close(descriptor)
        finally:
            os.close(directory_descriptor)

    def _assert_session_directory_current(self) -> None:
        descriptor = _open_bound_session_directory(
            self.path, self._directory_identity
        )
        os.close(descriptor)

    def _reload_state_locked(self) -> None:
        state = read_json(self.state_path)
        _validate_state(state)
        self._state = state

    def _persist_state(self, state: dict[str, object]) -> None:
        _validate_state(state)
        self.assert_operation_lock_current()
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
    expected_fields = {
        "admin_scripts",
        "created_at",
        "critical_stop",
        "events",
        "issues",
        "manifest",
        "mutation_intent",
        "schema_version",
        "targets",
    }
    if set(state) != expected_fields:
        raise ValueError("state fields do not match schema version 1")
    for key, expected in (("created_at", str), ("events", list), ("issues", list), ("targets", dict)):
        if not isinstance(state.get(key), expected):
            raise ValueError(f"state {key} must be a {expected.__name__}")
    admin_scripts = state.get("admin_scripts", {})
    if not isinstance(admin_scripts, Mapping):
        raise ValueError("state admin_scripts must be an object")
    for batch_id, binding in admin_scripts.items():
        if not isinstance(batch_id, str) or not isinstance(binding, Mapping):
            raise ValueError("state administrative script binding is malformed")
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
    intent = state.get("mutation_intent")
    if intent is not None:
        _validate_mutation_intent(intent)
        if record is None:
            raise ValueError("state mutation_intent requires a manifest record")
        value = record["value"]
        assert isinstance(value, Mapping)
        manifest = Manifest.from_dict(value)
        batches = tuple(
            batch for batch in manifest.batches if batch.id == intent["batch_id"]
        )
        if len(batches) != 1 or intent["target_id"] not in {
            target.id for target in batches[0].targets
        }:
            raise ValueError("state mutation_intent is not bound to its manifest")


def _validate_mutation_intent(value: object) -> None:
    if not isinstance(value, Mapping):
        raise ValueError("state mutation_intent must be an object or null")
    expected = {
        "batch_id",
        "created_at",
        "operation",
        "operation_id",
        "schema_version",
        "target_id",
    }
    if (
        set(value) != expected
        or type(value.get("schema_version")) is not int
        or value.get("schema_version") != SCHEMA_VERSION
    ):
        raise ValueError("state mutation_intent fields do not match schema")
    if value.get("operation") != "apply":
        raise ValueError("state mutation_intent operation is invalid")
    if not isinstance(value.get("created_at"), str) or re.fullmatch(
        r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z", value["created_at"]
    ) is None:
        raise ValueError("state mutation_intent timestamp is invalid")
    if not isinstance(value.get("batch_id"), str) or not value["batch_id"]:
        raise ValueError("state mutation_intent batch id is invalid")
    if not isinstance(value.get("target_id"), str) or not value["target_id"]:
        raise ValueError("state mutation_intent target id is invalid")
    operation_id = value.get("operation_id")
    if not isinstance(operation_id, str) or re.fullmatch(
        r"[0-9a-f]{32}", operation_id
    ) is None:
        raise ValueError("state mutation_intent operation id is invalid")


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
