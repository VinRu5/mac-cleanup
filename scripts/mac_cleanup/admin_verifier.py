"""Self-contained immutable verifier copied into generated session artifacts.

This module intentionally imports only the Python standard library.  The generator
copies its exact bytes into the session; the administrative script verifies and
executes those bytes without importing this package.
"""

from __future__ import annotations

import fcntl
import hashlib
import hmac
import json
import os
import secrets
import stat
import sys
from datetime import datetime, timezone


RESULT_SCHEMA_VERSION = 1
_READ_LIMIT = 16 * 1024 * 1024
_LOCK_ACQUIRE_ATTEMPTS = 8
_SUPPORTED_RISKS = {
    "safe-user-caches": "safe_regenerable",
    "review-user-caches": "review_required",
}


class SafetyError(RuntimeError):
    def __init__(self, message: str, *, critical: bool = False) -> None:
        super().__init__(message)
        self.critical = critical


def _canonical_bytes(value: object) -> bytes:
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _sha256(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _is_sha256(value: object) -> bool:
    return (
        isinstance(value, str)
        and len(value) == 64
        and all(character in "0123456789abcdef" for character in value)
    )


def _open_flags(*, directory: bool) -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise SafetyError("O_NOFOLLOW is unavailable", critical=True)
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if directory:
        flags |= os.O_DIRECTORY
    return flags


def _absolute_directory(path: str, label: str) -> int:
    if not isinstance(path, str) or not os.path.isabs(path):
        raise SafetyError(f"{label} must be absolute", critical=True)
    if os.path.normpath(path) != path or "\0" in path:
        raise SafetyError(f"{label} must be canonical", critical=True)
    descriptor = os.open("/", _open_flags(directory=True))
    try:
        for part in path.split("/")[1:]:
            if not part:
                continue
            child = os.open(part, _open_flags(directory=True), dir_fd=descriptor)
            os.close(descriptor)
            descriptor = child
        if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
            raise SafetyError(f"{label} is not a directory", critical=True)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _artifact_name(path: str, session_path: str, label: str) -> str:
    if (
        not isinstance(path, str)
        or not os.path.isabs(path)
        or os.path.normpath(path) != path
        or os.path.dirname(path) != session_path
        or os.path.basename(path) in {"", ".", ".."}
        or "\0" in path
    ):
        raise SafetyError(f"{label} is outside the trusted session", critical=True)
    return os.path.basename(path)


def _same_stat(first: os.stat_result, second: os.stat_result) -> bool:
    return (
        first.st_dev,
        first.st_ino,
        stat.S_IFMT(first.st_mode),
        first.st_uid,
        first.st_gid,
        first.st_mtime_ns,
        first.st_size,
    ) == (
        second.st_dev,
        second.st_ino,
        stat.S_IFMT(second.st_mode),
        second.st_uid,
        second.st_gid,
        second.st_mtime_ns,
        second.st_size,
    )


def _read_regular_at(
    directory_fd: int,
    name: str,
    label: str,
    *,
    owner: int | None = None,
    group: int | None = None,
    mode: int | None = None,
) -> bytes:
    descriptor = os.open(name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=directory_fd)
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode):
            raise SafetyError(f"{label} is not a regular file", critical=True)
        if owner is not None and before.st_uid != owner:
            raise SafetyError(f"{label} owner changed", critical=True)
        if group is not None and before.st_gid != group:
            raise SafetyError(f"{label} group changed", critical=True)
        if mode is not None and stat.S_IMODE(before.st_mode) != mode:
            raise SafetyError(f"{label} mode changed", critical=True)
        if before.st_size > _READ_LIMIT:
            raise SafetyError(f"{label} is unexpectedly large", critical=True)
        chunks: list[bytes] = []
        remaining = before.st_size
        while remaining:
            chunk = os.read(descriptor, min(remaining, 1048576))
            if not chunk:
                raise SafetyError(f"{label} was truncated", critical=True)
            chunks.append(chunk)
            remaining -= len(chunk)
        if os.read(descriptor, 1):
            raise SafetyError(f"{label} grew while reading", critical=True)
        after = os.fstat(descriptor)
        if not _same_stat(before, after):
            raise SafetyError(f"{label} changed while reading", critical=True)
        return b"".join(chunks)
    finally:
        os.close(descriptor)


def _read_json_at(
    directory_fd: int,
    name: str,
    label: str,
    *,
    owner: int | None = None,
    group: int | None = None,
    mode: int | None = None,
) -> dict[str, object]:
    try:
        value = json.loads(
            _read_regular_at(
                directory_fd,
                name,
                label,
                owner=owner,
                group=group,
                mode=mode,
            ).decode("utf-8")
        )
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise SafetyError(f"{label} is not JSON", critical=True) from error
    if not isinstance(value, dict):
        raise SafetyError(f"{label} root is not an object", critical=True)
    return value


def _require_current_lock(session_fd: int, lock_fd: int) -> None:
    try:
        current = os.stat(
            ".session.lock", dir_fd=session_fd, follow_symlinks=False
        )
    except FileNotFoundError as error:
        raise SafetyError("session lock pathname disappeared", critical=True) from error
    locked = os.fstat(lock_fd)
    if (current.st_dev, current.st_ino) != (locked.st_dev, locked.st_ino):
        raise SafetyError("session lock pathname was replaced", critical=True)


def _acquire_stable_lock(session_fd: int, uid: int, gid: int) -> int:
    """Acquire the inode currently named by the session lock pathname."""
    for _ in range(_LOCK_ACQUIRE_ATTEMPTS):
        descriptor = os.open(
            ".session.lock", os.O_RDWR | os.O_NOFOLLOW, dir_fd=session_fd
        )
        try:
            lock_stat = os.fstat(descriptor)
            if (
                not stat.S_ISREG(lock_stat.st_mode)
                or lock_stat.st_uid != uid
                or lock_stat.st_gid != gid
                or stat.S_IMODE(lock_stat.st_mode) != 0o600
            ):
                raise SafetyError("session lock changed", critical=True)
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            try:
                _require_current_lock(session_fd, descriptor)
            except SafetyError:
                fcntl.flock(descriptor, fcntl.LOCK_UN)
            else:
                return descriptor
        except BaseException:
            os.close(descriptor)
            raise
        os.close(descriptor)
    raise SafetyError("session lock pathname did not stabilize", critical=True)


def _owned_temp(
    directory_fd: int, destination_name: str, uid: int, gid: int, mode: int
) -> tuple[int, str]:
    if type(uid) is not int or uid < 0 or type(gid) is not int or gid < 0:
        raise SafetyError("bound owner is invalid", critical=True)
    for _ in range(32):
        temporary = f".{destination_name}.{secrets.token_hex(12)}"
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                mode,
                dir_fd=directory_fd,
            )
            break
        except FileExistsError:
            continue
    else:
        raise SafetyError("cannot allocate result checkpoint", critical=True)
    try:
        if os.geteuid() == 0:
            os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, mode)
        current = os.fstat(descriptor)
        if (
            not stat.S_ISREG(current.st_mode)
            or current.st_uid != uid
            or current.st_gid != gid
            or stat.S_IMODE(current.st_mode) != mode
        ):
            raise SafetyError("checkpoint owner or mode is unsafe", critical=True)
        return descriptor, temporary
    except BaseException:
        os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        raise


def _atomic_write_json_owned_at(
    directory_fd: int, name: str, value: object, uid: int, gid: int
) -> None:
    payload = _canonical_bytes(value)
    descriptor, temporary = _owned_temp(directory_fd, name, uid, gid, 0o600)
    try:
        view = memoryview(payload)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise SafetyError("cannot write result checkpoint", critical=True)
            view = view[written:]
        os.fsync(descriptor)
        current = os.fstat(descriptor)
        if (
            current.st_uid != uid
            or current.st_gid != gid
            or stat.S_IMODE(current.st_mode) != 0o600
        ):
            raise SafetyError("checkpoint owner or mode changed", critical=True)
        os.close(descriptor)
        descriptor = -1
        os.replace(
            temporary,
            name,
            src_dir_fd=directory_fd,
            dst_dir_fd=directory_fd,
        )
        os.fsync(directory_fd)
        final = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(final.st_mode)
            or final.st_uid != uid
            or final.st_gid != gid
            or stat.S_IMODE(final.st_mode) != 0o600
        ):
            raise SafetyError("published checkpoint is unsafe", critical=True)
    except BaseException:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        raise


def _atomic_write_json_owned(
    path: str, value: object, uid: int, gid: int
) -> None:
    """Test seam; real execution uses the descriptor-relative helper directly."""
    parent = os.path.dirname(path)
    name = _artifact_name(path, parent, "owned JSON destination")
    directory_fd = _absolute_directory(parent, "owned JSON parent")
    try:
        _atomic_write_json_owned_at(directory_fd, name, value, uid, gid)
    finally:
        os.close(directory_fd)


def _validate_manifest_record(state: dict[str, object]) -> dict[str, object]:
    expected = {
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
    if (
        set(state) != expected
        or type(state.get("schema_version")) is not int
        or state.get("schema_version") != 2
    ):
        raise SafetyError("state schema is invalid", critical=True)
    record = state.get("manifest")
    if not isinstance(record, dict) or set(record) != {
        "digest",
        "target_ids",
        "value",
    }:
        raise SafetyError("state manifest record is malformed", critical=True)
    value = record["value"]
    target_ids = record["target_ids"]
    if (
        not isinstance(value, dict)
        or not isinstance(target_ids, list)
        or not all(isinstance(item, str) for item in target_ids)
        or target_ids != sorted(target_ids)
        or not _is_sha256(record["digest"])
        or not hmac.compare_digest(_sha256(_canonical_bytes(value)), record["digest"])
    ):
        raise SafetyError("state manifest binding is invalid", critical=True)
    discovered: list[str] = []
    batches = value.get("batches")
    if not isinstance(batches, list):
        raise SafetyError("manifest batches are invalid", critical=True)
    for batch in batches:
        if not isinstance(batch, dict) or not isinstance(batch.get("targets"), list):
            raise SafetyError("manifest batch is invalid", critical=True)
        for target in batch["targets"]:
            if not isinstance(target, dict) or not isinstance(target.get("id"), str):
                raise SafetyError("manifest target is invalid", critical=True)
            discovered.append(target["id"])
    if sorted(discovered) != target_ids or len(discovered) != len(set(discovered)):
        raise SafetyError("manifest target ids diverged", critical=True)
    return record


def _operation_digest(binding: dict[str, object]) -> str:
    value = {
        "allowed_root": binding["allowed_root"],
        "batch": binding["batch"],
        "checksum": binding["checksum"],
        "manifest_digest": binding["manifest_digest"],
        "output_path": binding["output_path"],
        "result_path": binding["result_path"],
        "session_path": binding["session_path"],
        "session_gid": binding["session_gid"],
        "session_uid": binding["session_uid"],
        "snapshot_digest": binding["snapshot_digest"],
        "snapshot_path": binding["snapshot_path"],
    }
    return _sha256(_canonical_bytes(value))


def _validate_binding(
    state: dict[str, object],
    manifest_record: dict[str, object],
    batch_id: str,
    operation_digest: str,
    snapshot_path: str,
    snapshot_digest: str,
    script_path: str,
    result_path: str,
    allowed_root: str,
    session_uid: int,
    session_gid: int,
    target: dict[str, object],
    expected_intent: dict[str, object] | None = None,
) -> dict[str, object]:
    scripts = state.get("admin_scripts")
    if not isinstance(scripts, dict):
        raise SafetyError("administrative bindings are malformed", critical=True)
    binding = scripts.get(batch_id)
    keys = {
        "allowed_root",
        "batch",
        "batch_id",
        "checksum",
        "manifest_digest",
        "operation_digest",
        "output_path",
        "result_path",
        "session_path",
        "session_gid",
        "session_uid",
        "snapshot_digest",
        "snapshot_path",
        "target_ids",
    }
    if not isinstance(binding, dict) or set(binding) != keys:
        raise SafetyError("administrative binding schema changed", critical=True)
    expected = {
        "allowed_root": allowed_root,
        "batch_id": batch_id,
        "manifest_digest": manifest_record["digest"],
        "operation_digest": operation_digest,
        "output_path": script_path,
        "result_path": result_path,
        "session_path": os.path.dirname(result_path),
        "session_gid": session_gid,
        "session_uid": session_uid,
        "snapshot_digest": snapshot_digest,
        "snapshot_path": snapshot_path,
    }
    for key, value in expected.items():
        if binding.get(key) != value:
            raise SafetyError(f"administrative binding changed: {key}", critical=True)
    if not _is_sha256(binding["checksum"]):
        raise SafetyError("administrative checksum is invalid", critical=True)
    if not hmac.compare_digest(_operation_digest(binding), operation_digest):
        raise SafetyError("administrative operation digest changed", critical=True)
    manifest = manifest_record["value"]
    assert isinstance(manifest, dict)
    batches = [
        batch
        for batch in manifest["batches"]
        if isinstance(batch, dict) and batch.get("id") == batch_id
    ]
    if len(batches) != 1 or binding["batch"] != batches[0]:
        raise SafetyError("administrative batch changed", critical=True)
    batch = binding["batch"]
    assert isinstance(batch, dict)
    members = batch.get("targets")
    if not isinstance(members, list):
        raise SafetyError("administrative targets changed", critical=True)
    target_ids = [item.get("id") for item in members if isinstance(item, dict)]
    if (
        binding["target_ids"] != target_ids
        or target_ids != list(dict.fromkeys(target_ids))
    ):
        raise SafetyError("administrative target ordering changed", critical=True)
    matches = [item for item in members if item.get("id") == target["id"]]
    if len(matches) != 1 or matches[0] != target:
        raise SafetyError("administrative target changed", critical=True)
    targets = state.get("targets")
    if not isinstance(targets, dict) or targets.get(target["id"]) != "approved":
        raise SafetyError("administrative target is no longer approved", critical=True)
    if state.get("critical_stop") is not None:
        raise SafetyError("session has a critical safety stop", critical=True)
    if state.get("mutation_intent") != expected_intent:
        raise SafetyError("session has an unrelated mutation intent", critical=True)
    return binding


def _new_admin_intent(
    batch_id: str, target_id: str, operation_digest: str
) -> dict[str, object]:
    return {
        "batch_id": batch_id,
        "created_at": datetime.now(timezone.utc)
        .isoformat(timespec="microseconds")
        .replace("+00:00", "Z"),
        "operation": "admin_apply",
        "operation_binding": operation_digest,
        "operation_id": secrets.token_hex(16),
        "primary_issue": None,
        "schema_version": 1,
        "target_id": target_id,
    }


def _record_intent_issue(
    session_fd: int,
    lock_fd: int,
    intent: dict[str, object],
    issue: dict[str, object],
    uid: int,
    gid: int,
) -> None:
    _require_current_lock(session_fd, lock_fd)
    state = _read_json_at(
        session_fd, "state.json", "state", owner=uid, group=gid, mode=0o600
    )
    _validate_manifest_record(state)
    if state.get("mutation_intent") != intent:
        raise SafetyError("mutation intent changed", critical=True)
    if intent.get("primary_issue") is not None:
        return
    next_intent = dict(intent)
    next_intent["primary_issue"] = issue
    next_state = json.loads(_canonical_bytes(state).decode("utf-8"))
    next_state["mutation_intent"] = next_intent
    _atomic_write_json_owned_at(session_fd, "state.json", next_state, uid, gid)
    intent.clear()
    intent.update(next_intent)


def _validate_result(
    value: object,
    batch_id: str,
    operation_digest: str,
    target_ids: object,
) -> dict[str, object]:
    keys = {"schema_version", "batch_id", "operation_digest", "target_ids", "targets"}
    if (
        not isinstance(value, dict)
        or set(value) != keys
        or value.get("schema_version") != RESULT_SCHEMA_VERSION
        or value.get("batch_id") != batch_id
        or value.get("operation_digest") != operation_digest
        or value.get("target_ids") != target_ids
        or not isinstance(value.get("targets"), dict)
        or not isinstance(target_ids, list)
        or not set(value["targets"]).issubset(set(target_ids))
    ):
        raise SafetyError("administrative result binding changed", critical=True)
    records = value["targets"]
    assert isinstance(records, dict)
    for target_id, record in records.items():
        if not isinstance(target_id, str) or not isinstance(record, dict):
            raise SafetyError("administrative target result is malformed", critical=True)
        if set(record) != {"issues", "logical_bytes_removed", "status"}:
            raise SafetyError("administrative result fields changed", critical=True)
        if record["status"] not in {"verified", "suspended"}:
            raise SafetyError("administrative result status changed", critical=True)
        removed = record["logical_bytes_removed"]
        if type(removed) is not int or removed < 0:
            raise SafetyError("administrative result byte count changed", critical=True)
        issues = record["issues"]
        if not isinstance(issues, list):
            raise SafetyError("administrative result issues changed", critical=True)
        for issue in issues:
            if not isinstance(issue, dict) or set(issue) not in (
                {"code", "severity", "message"},
                {"code", "severity", "message", "target_id"},
            ):
                raise SafetyError("administrative result issue changed", critical=True)
            if (
                not isinstance(issue["code"], str)
                or issue["severity"]
                not in {"informational", "warning", "batch_error", "critical"}
                or not isinstance(issue["message"], str)
                or (
                    "target_id" in issue
                    and not isinstance(issue["target_id"], str)
                )
            ):
                raise SafetyError("administrative result issue is invalid", critical=True)
    return value


def _target_contract(
    target: dict[str, object], batch_id: str, allowed_root: str
) -> str:
    keys = {"fingerprint", "id", "kind", "logical_bytes", "path", "risk", "status"}
    if set(target) != keys or not isinstance(target.get("id"), str):
        raise SafetyError("target descriptor schema changed", critical=True)
    prefix, separator, name = target["id"].partition(":")
    expected_risk = _SUPPORTED_RISKS.get(batch_id)
    if (
        prefix != "user-caches"
        or not separator
        or not name
        or "/" in name
        or target["path"] != f"{allowed_root}/{name}"
        or target["kind"] not in {"file", "directory"}
        or target["risk"] != expected_risk
        or target["status"] != "pending"
        or not _is_sha256(target["fingerprint"])
        or type(target["logical_bytes"]) is not int
        or target["logical_bytes"] < 0
    ):
        raise SafetyError("target is outside the administrative contract", critical=True)
    return name


def _kind(path_stat: os.stat_result) -> str:
    if stat.S_ISREG(path_stat.st_mode):
        return "file"
    if stat.S_ISDIR(path_stat.st_mode):
        return "directory"
    raise SafetyError("target is not a regular file or directory", critical=True)


def _descendant_record(
    relative: str, kind: str, path_stat: os.stat_result
) -> str:
    return "\0".join(
        (
            relative,
            kind,
            str(path_stat.st_uid),
            str(path_stat.st_dev),
            str(path_stat.st_ino),
            str(path_stat.st_mtime_ns),
            str(path_stat.st_size),
        )
    )


def _tree_snapshot(
    directory_fd: int, directory_stat: os.stat_result, relative: str
) -> tuple[int, tuple[str, ...]]:
    if _kind(directory_stat) == "file":
        return directory_stat.st_size, ()
    total = 0
    records: list[str] = []
    with os.scandir(directory_fd) as entries:
        for entry in sorted(entries, key=lambda item: item.name):
            entry_stat = entry.stat(follow_symlinks=False)
            if entry.is_symlink():
                raise SafetyError(
                    f"symlink found in target: {entry.name}", critical=True
                )
            entry_kind = _kind(entry_stat)
            child_relative = f"{relative}/{entry.name}"
            if entry_kind == "directory":
                child_fd = os.open(
                    entry.name, _open_flags(directory=True), dir_fd=directory_fd
                )
                try:
                    if not _same_stat(entry_stat, os.fstat(child_fd)):
                        raise SafetyError(
                            "target changed while opening", critical=True
                        )
                    child_bytes, child_records = _tree_snapshot(
                        child_fd, entry_stat, child_relative
                    )
                finally:
                    os.close(child_fd)
            else:
                child_bytes, child_records = entry_stat.st_size, ()
            total += child_bytes
            records.append(_descendant_record(child_relative, entry_kind, entry_stat))
            records.extend(child_records)
    return total, tuple(records)


def _fingerprint(
    canonical: str,
    kind: str,
    path_stat: os.stat_result,
    logical_bytes: int,
    descendants: tuple[str, ...],
) -> str:
    material = "\0".join(
        (
            canonical,
            kind,
            str(path_stat.st_uid),
            str(path_stat.st_dev),
            str(path_stat.st_ino),
            str(path_stat.st_mtime_ns),
            str(logical_bytes),
            *descendants,
        )
    )
    return _sha256(material.encode("utf-8"))


def _open_target(
    root_fd: int, name: str
) -> tuple[int, os.stat_result, str] | None:
    try:
        target_stat = os.stat(name, dir_fd=root_fd, follow_symlinks=False)
    except FileNotFoundError:
        return None
    if stat.S_ISLNK(target_stat.st_mode):
        raise SafetyError("target became a symlink", critical=True)
    kind = _kind(target_stat)
    descriptor = os.open(
        name, _open_flags(directory=kind == "directory"), dir_fd=root_fd
    )
    try:
        current = os.fstat(descriptor)
        if not _same_stat(target_stat, current):
            raise SafetyError("target changed while opening", critical=True)
        return descriptor, current, kind
    except BaseException:
        os.close(descriptor)
        raise


def _inspect_target(
    root_fd: int, name: str, target: dict[str, object]
) -> tuple[int, os.stat_result, str, int] | None:
    opened = _open_target(root_fd, name)
    if opened is None:
        return None
    descriptor, target_stat, kind = opened
    logical_bytes, descendants = _tree_snapshot(descriptor, target_stat, ".")
    current_fingerprint = _fingerprint(
        str(target["path"]), kind, target_stat, logical_bytes, descendants
    )
    if (
        kind != target["kind"]
        or logical_bytes != target["logical_bytes"]
        or not hmac.compare_digest(current_fingerprint, str(target["fingerprint"]))
    ):
        os.close(descriptor)
        raise SafetyError("target identity changed after approval")
    return descriptor, target_stat, kind, logical_bytes


def _stat_at(parent_fd: int, name: str) -> os.stat_result:
    current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    if stat.S_ISLNK(current.st_mode):
        raise SafetyError("target became a symlink", critical=True)
    return current


def _unlink_exact(parent_fd: int, name: str, descriptor: int) -> None:
    if not _same_stat(os.fstat(descriptor), _stat_at(parent_fd, name)):
        raise SafetyError("file changed before deletion", critical=True)
    os.unlink(name, dir_fd=parent_fd)


def _remove_directory_exact(parent_fd: int, name: str, directory_fd: int) -> None:
    with os.scandir(directory_fd) as entries:
        for entry in sorted(entries, key=lambda item: item.name):
            entry_stat = entry.stat(follow_symlinks=False)
            if entry.is_symlink():
                raise SafetyError("symlink found during deletion", critical=True)
            entry_kind = _kind(entry_stat)
            child_fd = os.open(
                entry.name,
                _open_flags(directory=entry_kind == "directory"),
                dir_fd=directory_fd,
            )
            try:
                if not _same_stat(entry_stat, os.fstat(child_fd)):
                    raise SafetyError("target changed during deletion", critical=True)
                if entry_kind == "directory":
                    _remove_directory_exact(directory_fd, entry.name, child_fd)
                else:
                    _unlink_exact(directory_fd, entry.name, child_fd)
            finally:
                os.close(child_fd)
    if not _same_stat(os.fstat(directory_fd), _stat_at(parent_fd, name)):
        raise SafetyError("directory changed before deletion", critical=True)
    os.rmdir(name, dir_fd=parent_fd)


def _issue(
    code: str, severity: str, message: str, target_id: object
) -> dict[str, object]:
    return {
        "code": code,
        "severity": severity,
        "message": message,
        "target_id": target_id,
    }


def _checkpoint(
    session_fd: int,
    lock_fd: int,
    result_name: str,
    results: dict[str, object],
    target_id: str,
    status: str,
    issues: list[dict[str, object]],
    removed: int,
    uid: int,
    gid: int,
) -> None:
    _require_current_lock(session_fd, lock_fd)
    next_value = json.loads(_canonical_bytes(results).decode("utf-8"))
    targets = next_value["targets"]
    assert isinstance(targets, dict)
    targets[target_id] = {
        "issues": issues,
        "logical_bytes_removed": removed,
        "status": status,
    }
    _atomic_write_json_owned_at(session_fd, result_name, next_value, uid, gid)


def _run(arguments: tuple[str, ...]) -> int:
    if len(arguments) != 15:
        return 64
    (
        session_path,
        snapshot_path,
        snapshot_digest,
        script_path,
        result_path,
        operation_digest,
        batch_id,
        target_json,
        allowed_root,
        uid_text,
        gid_text,
        expected_manifest_digest,
        expected_target_id,
        expected_target_path,
        expected_target_fingerprint,
    ) = arguments
    session_fd = -1
    lock_fd = -1
    root_fd = -1
    target_fd = -1
    results: dict[str, object] | None = None
    target: dict[str, object] | None = None
    result_name: str | None = None
    uid = -1
    gid = -1
    intent: dict[str, object] | None = None
    try:
        if not _is_sha256(snapshot_digest) or not _is_sha256(operation_digest):
            raise SafetyError("generated digests are invalid", critical=True)
        if not _is_sha256(expected_manifest_digest) or not _is_sha256(
            expected_target_fingerprint
        ):
            raise SafetyError("generated binding is invalid", critical=True)
        uid = int(uid_text)
        gid = int(gid_text)
        parsed_target = json.loads(target_json)
        if not isinstance(parsed_target, dict):
            raise SafetyError("generated target is invalid", critical=True)
        target = parsed_target
        if target.get("id") != expected_target_id:
            raise SafetyError("generated target descriptor changed", critical=True)
        if target.get("path") != expected_target_path:
            raise SafetyError("generated target path changed", critical=True)
        if target.get("fingerprint") != expected_target_fingerprint:
            raise SafetyError("generated target fingerprint changed", critical=True)
        session_fd = _absolute_directory(session_path, "session")
        session_stat = os.fstat(session_fd)
        if session_stat.st_uid != uid or session_stat.st_gid != gid:
            raise SafetyError("session owner changed", critical=True)
        snapshot_name = _artifact_name(snapshot_path, session_path, "snapshot")
        script_name = _artifact_name(script_path, session_path, "script")
        result_name = _artifact_name(result_path, session_path, "result")
        if len({snapshot_name, script_name, result_name}) != 3:
            raise SafetyError("administrative artifacts overlap", critical=True)
        lock_fd = _acquire_stable_lock(session_fd, uid, gid)

        # Reload durable authorization only after acquiring the stable session lock.
        state = _read_json_at(
            session_fd, "state.json", "state", owner=uid, group=gid, mode=0o600
        )
        manifest_record = _validate_manifest_record(state)
        if manifest_record["digest"] != expected_manifest_digest:
            raise SafetyError("manifest digest changed", critical=True)
        manifest_bytes = _read_regular_at(
            session_fd,
            "manifest.json",
            "manifest",
            owner=uid,
            group=gid,
            mode=0o600,
        )
        manifest_value = manifest_record["value"]
        if (
            manifest_bytes != _canonical_bytes(manifest_value)
            or not hmac.compare_digest(
                _sha256(manifest_bytes), str(manifest_record["digest"])
            )
        ):
            raise SafetyError("manifest artifact changed", critical=True)
        binding = _validate_binding(
            state,
            manifest_record,
            batch_id,
            operation_digest,
            snapshot_path,
            snapshot_digest,
            script_path,
            result_path,
            allowed_root,
            uid,
            gid,
            target,
        )
        script_bytes = _read_regular_at(
            session_fd,
            script_name,
            "script",
            owner=uid,
            group=gid,
            mode=0o700,
        )
        if not hmac.compare_digest(_sha256(script_bytes), str(binding["checksum"])):
            raise SafetyError(
                "administrative script checksum changed", critical=True
            )
        result_bytes = _read_regular_at(
            session_fd,
            result_name,
            "result",
            owner=uid,
            group=gid,
            mode=0o600,
        )
        try:
            result_value = json.loads(result_bytes.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise SafetyError("result is not JSON", critical=True) from error
        results = _validate_result(
            result_value, batch_id, operation_digest, binding["target_ids"]
        )
        name = _target_contract(target, batch_id, allowed_root)
        root_fd = _absolute_directory(allowed_root, "allowed root")
        inspected = _inspect_target(root_fd, name, target)
        if inspected is None:
            issues = [
                _issue(
                    "executor.target-absent",
                    "informational",
                    f"Target is already absent: {target['path']}",
                    target["id"],
                )
            ]
            _checkpoint(
                session_fd,
                lock_fd,
                result_name,
                results,
                str(target["id"]),
                "verified",
                issues,
                0,
                uid,
                gid,
            )
            return 0
        target_fd, _target_stat, target_kind, removed = inspected
        # A replacement after acquisition would split direct and administrative
        # operations across different inodes.  Recheck both durable authority and
        # the named lock immediately before the first destructive syscall.
        _require_current_lock(session_fd, lock_fd)
        current_state = _read_json_at(
            session_fd, "state.json", "state", owner=uid, group=gid, mode=0o600
        )
        current_manifest = _validate_manifest_record(current_state)
        current_binding = _validate_binding(
            current_state,
            current_manifest,
            batch_id,
            operation_digest,
            snapshot_path,
            snapshot_digest,
            script_path,
            result_path,
            allowed_root,
            uid,
            gid,
            target,
        )
        if not hmac.compare_digest(
            str(current_binding["checksum"]), str(binding["checksum"])
        ):
            raise SafetyError(
                "administrative checksum binding changed", critical=True
            )
        current_script = _read_regular_at(
            session_fd,
            script_name,
            "script",
            owner=uid,
            group=gid,
            mode=0o700,
        )
        if not hmac.compare_digest(
            _sha256(current_script), str(current_binding["checksum"])
        ):
            raise SafetyError(
                "administrative script checksum changed", critical=True
            )
        intent = _new_admin_intent(
            batch_id, str(target["id"]), operation_digest
        )
        next_state = json.loads(_canonical_bytes(current_state).decode("utf-8"))
        next_state["mutation_intent"] = intent
        _atomic_write_json_owned_at(session_fd, "state.json", next_state, uid, gid)
        committed_state = _read_json_at(
            session_fd, "state.json", "state", owner=uid, group=gid, mode=0o600
        )
        committed_manifest = _validate_manifest_record(committed_state)
        _validate_binding(
            committed_state,
            committed_manifest,
            batch_id,
            operation_digest,
            snapshot_path,
            snapshot_digest,
            script_path,
            result_path,
            allowed_root,
            uid,
            gid,
            target,
            expected_intent=intent,
        )
        committed_script = _read_regular_at(
            session_fd,
            script_name,
            "script",
            owner=uid,
            group=gid,
            mode=0o700,
        )
        if not hmac.compare_digest(
            _sha256(committed_script), str(current_binding["checksum"])
        ):
            raise SafetyError(
                "administrative script checksum changed", critical=True
            )
        _require_current_lock(session_fd, lock_fd)
        if target_kind == "directory":
            _remove_directory_exact(root_fd, name, target_fd)
        else:
            _unlink_exact(root_fd, name, target_fd)
        try:
            os.stat(name, dir_fd=root_fd, follow_symlinks=False)
        except FileNotFoundError:
            pass
        else:
            raise SafetyError("target remains after deletion")
        _checkpoint(
            session_fd,
            lock_fd,
            result_name,
            results,
            str(target["id"]),
            "verified",
            [],
            removed,
            uid,
            gid,
        )
        return 0
    except SafetyError as error:
        if (
            results is not None
            and target is not None
            and result_name is not None
            and session_fd >= 0
        ):
            severity = "critical" if error.critical else "batch_error"
            code = "paths.unsafe-target" if error.critical else "executor.target-changed"
            issue = _issue(code, severity, str(error), target.get("id"))
            if intent is not None:
                try:
                    _record_intent_issue(
                        session_fd, lock_fd, intent, issue, uid, gid
                    )
                except BaseException:
                    pass
            try:
                _checkpoint(
                    session_fd,
                    lock_fd,
                    result_name,
                    results,
                    str(target.get("id")),
                    "suspended",
                    [issue],
                    0,
                    uid,
                    gid,
                )
            except BaseException:
                pass
            return 4 if error.critical else 3
        return 64
    except OSError as error:
        if (
            results is not None
            and target is not None
            and result_name is not None
            and session_fd >= 0
        ):
            issue = _issue(
                "executor.os-error",
                "batch_error",
                f"Filesystem operation failed: {error}",
                target.get("id"),
            )
            if intent is not None:
                try:
                    _record_intent_issue(
                        session_fd, lock_fd, intent, issue, uid, gid
                    )
                except BaseException:
                    pass
            try:
                _checkpoint(
                    session_fd,
                    lock_fd,
                    result_name,
                    results,
                    str(target.get("id")),
                    "suspended",
                    [issue],
                    0,
                    uid,
                    gid,
                )
            except BaseException:
                pass
            return 3
        return 64
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return 64
    finally:
        if target_fd >= 0:
            os.close(target_fd)
        if root_fd >= 0:
            os.close(root_fd)
        if lock_fd >= 0:
            try:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
            finally:
                os.close(lock_fd)
        if session_fd >= 0:
            os.close(session_fd)


def _main(arguments: list[str] | tuple[str, ...]) -> int:
    return _run(tuple(arguments))


if __name__ == "__main__":
    raise SystemExit(_main(sys.argv[1:]))
