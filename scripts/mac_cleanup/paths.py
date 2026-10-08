"""Conservative filesystem identity and deletion helpers."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import os
from pathlib import Path
import stat
from typing import Iterable


class PathSafetyError(RuntimeError):
    """Raised when a path cannot be safely inspected or removed."""


@dataclass(frozen=True)
class PathIdentity:
    """Filesystem facts captured for a single approved cleanup target."""

    requested: str
    canonical: str
    kind: str
    owner_uid: int
    device: int
    inode: int
    mtime_ns: int
    logical_bytes: int
    fingerprint: str


def inspect_path(
    path: str | os.PathLike[str], allowed_roots: Iterable[str | os.PathLike[str]]
) -> PathIdentity:
    """Inspect an existing regular file or directory strictly below an allowed root."""
    candidate = _absolute_path(path, "target")
    candidate_stat = _lstat(candidate, "target")
    _reject_symlink(candidate, candidate_stat)
    _reject_symlink_components(candidate)
    canonical = candidate.resolve(strict=True)

    if canonical == Path("/") or canonical == Path.home().resolve():
        raise PathSafetyError(f"broad cleanup target is not allowed: {canonical}")

    canonical_roots = tuple(_allowed_root(root) for root in allowed_roots)
    if not canonical_roots:
        raise PathSafetyError("at least one allowed root is required")
    if not any(_strictly_below(canonical, root) for root in canonical_roots):
        raise PathSafetyError(f"target is outside allowed roots: {canonical}")

    return _identity(str(path), canonical)


def remove_tree_exact(identity: PathIdentity) -> int:
    """Delete exactly the unchanged file or directory represented by ``identity``.

    The caller must retain the identity returned by :func:`inspect_path`; a changed
    target is rejected rather than removed. A target that has already disappeared
    is an idempotent no-op.
    """
    canonical = _absolute_path(identity.canonical, "identity canonical path")
    if canonical == Path("/") or canonical == Path.home().resolve():
        raise PathSafetyError(f"broad cleanup target is not allowed: {canonical}")

    try:
        canonical.lstat()
    except FileNotFoundError:
        return 0
    except OSError as error:
        raise PathSafetyError(f"cannot inspect target: {canonical}") from error
    current = _identity(identity.requested, canonical)
    if not _matches(identity, current):
        raise PathSafetyError(f"target changed since inspection: {canonical}")

    if current.kind == "file":
        os.unlink(canonical)
    else:
        _remove_directory(canonical)
    return current.logical_bytes


def _absolute_path(path: str | os.PathLike[str], label: str) -> Path:
    raw = os.fspath(path)
    if not isinstance(raw, str):
        raise PathSafetyError(f"{label} must be a text path")
    candidate = Path(raw)
    if not candidate.is_absolute():
        raise PathSafetyError(f"{label} must be absolute: {raw}")
    if ".." in candidate.parts:
        raise PathSafetyError(f"{label} must not contain parent traversal: {raw}")
    return candidate


def _allowed_root(path: str | os.PathLike[str]) -> Path:
    root = _absolute_path(path, "allowed root")
    root_stat = _lstat(root, "allowed root")
    _reject_symlink(root, root_stat)
    _reject_symlink_components(root)
    canonical = root.resolve(strict=True)
    if not stat.S_ISDIR(_lstat(canonical, "allowed root").st_mode):
        raise PathSafetyError(f"allowed root must be a directory: {canonical}")
    return canonical


def _identity(requested: str, canonical: Path) -> PathIdentity:
    target_stat = _lstat(canonical, "target")
    _reject_symlink(canonical, target_stat)
    _reject_symlink_components(canonical)
    kind = _kind(canonical, target_stat)
    logical_bytes = _logical_bytes(canonical, target_stat)
    canonical_text = str(canonical)
    fingerprint = _fingerprint(canonical_text, kind, target_stat, logical_bytes)
    return PathIdentity(
        requested=requested,
        canonical=canonical_text,
        kind=kind,
        owner_uid=target_stat.st_uid,
        device=target_stat.st_dev,
        inode=target_stat.st_ino,
        mtime_ns=target_stat.st_mtime_ns,
        logical_bytes=logical_bytes,
        fingerprint=fingerprint,
    )


def _lstat(path: Path, label: str) -> os.stat_result:
    try:
        return path.lstat()
    except OSError as error:
        raise PathSafetyError(f"cannot inspect {label}: {path}") from error


def _reject_symlink(path: Path, path_stat: os.stat_result) -> None:
    if stat.S_ISLNK(path_stat.st_mode):
        raise PathSafetyError(f"symlinks are not allowed: {path}")


def _reject_symlink_components(path: Path) -> None:
    current = Path(path.parts[0])
    for part in path.parts[1:]:
        current /= part
        _reject_symlink(current, _lstat(current, "path component"))


def _strictly_below(path: Path, root: Path) -> bool:
    try:
        relative = path.relative_to(root)
    except ValueError:
        return False
    return relative != Path(".")


def _kind(path: Path, path_stat: os.stat_result) -> str:
    if stat.S_ISREG(path_stat.st_mode):
        return "file"
    if stat.S_ISDIR(path_stat.st_mode):
        return "directory"
    raise PathSafetyError(f"only regular files and directories may be removed: {path}")


def _logical_bytes(path: Path, path_stat: os.stat_result) -> int:
    kind = _kind(path, path_stat)
    if kind == "file":
        return path_stat.st_size

    total = 0
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                entry_path = Path(entry.path)
                entry_stat = entry.stat(follow_symlinks=False)
                if entry.is_symlink():
                    raise PathSafetyError(f"symlinks are not allowed: {entry_path}")
                total += _logical_bytes(entry_path, entry_stat)
    except OSError as error:
        raise PathSafetyError(f"cannot inspect directory contents: {path}") from error
    return total


def _fingerprint(
    canonical: str, kind: str, path_stat: os.stat_result, logical_bytes: int
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
        )
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _matches(expected: PathIdentity, current: PathIdentity) -> bool:
    return (
        expected.canonical,
        expected.kind,
        expected.owner_uid,
        expected.device,
        expected.inode,
        expected.mtime_ns,
        expected.logical_bytes,
        expected.fingerprint,
    ) == (
        current.canonical,
        current.kind,
        current.owner_uid,
        current.device,
        current.inode,
        current.mtime_ns,
        current.logical_bytes,
        current.fingerprint,
    )


def _remove_directory(path: Path) -> None:
    try:
        with os.scandir(path) as entries:
            for entry in entries:
                entry_path = Path(entry.path)
                entry_stat = entry.stat(follow_symlinks=False)
                if entry.is_symlink():
                    raise PathSafetyError(f"symlinks are not allowed: {entry_path}")
                if stat.S_ISDIR(entry_stat.st_mode):
                    _remove_directory(entry_path)
                elif stat.S_ISREG(entry_stat.st_mode):
                    os.unlink(entry_path)
                else:
                    raise PathSafetyError(
                        f"only regular files and directories may be removed: {entry_path}"
                    )
        os.rmdir(path)
    except OSError as error:
        raise PathSafetyError(f"cannot remove directory: {path}") from error
