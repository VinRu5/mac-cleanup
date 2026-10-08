"""Conservative filesystem identity and descriptor-relative deletion helpers."""

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


@dataclass
class _OpenedTarget:
    parent_fd: int
    target_fd: int
    name: str
    kind: str

    def close(self) -> None:
        os.close(self.target_fd)
        os.close(self.parent_fd)


def inspect_path(
    path: str | os.PathLike[str], allowed_roots: Iterable[str | os.PathLike[str]]
) -> PathIdentity:
    """Inspect an existing regular file or directory strictly below an allowed root."""
    candidate = _absolute_path(path, "target")
    candidate_stat = _lstat(candidate, "target")
    _reject_symlink(candidate, candidate_stat)
    _reject_symlink_components(candidate)
    canonical = candidate.resolve(strict=True)
    _reject_broad_target(canonical)
    roots = _canonical_roots(allowed_roots)
    _containing_root(canonical, roots)
    return _identity_from_path(str(path), canonical)


def remove_tree_exact(
    identity: PathIdentity, allowed_roots: Iterable[str | os.PathLike[str]]
) -> int:
    """Delete only an unchanged identity under the supplied allowed-root capability.

    Explicit roots are required because ``PathIdentity`` is public: otherwise an
    arbitrary identity could authorize mutation outside the approved manifest.
    """
    canonical = _absolute_path(identity.canonical, "identity canonical path")
    _reject_broad_target(canonical)
    root = _containing_root(canonical, _canonical_roots(allowed_roots))
    opened = _open_target_beneath(root, canonical)
    if opened is None:
        return 0
    try:
        current = _identity_from_fd(identity.requested, canonical, opened.target_fd)
        if not _matches(identity, current):
            raise PathSafetyError(f"target changed since inspection: {canonical}")
        if opened.kind == "file":
            _unlink_exact(opened.parent_fd, opened.name, opened.target_fd)
        else:
            _remove_directory_exact(opened.parent_fd, opened.name, opened.target_fd)
        return current.logical_bytes
    finally:
        opened.close()


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


def _canonical_roots(allowed_roots: Iterable[str | os.PathLike[str]]) -> tuple[Path, ...]:
    roots = tuple(_allowed_root(root) for root in allowed_roots)
    if not roots:
        raise PathSafetyError("at least one allowed root is required")
    return roots


def _allowed_root(path: str | os.PathLike[str]) -> Path:
    root = _absolute_path(path, "allowed root")
    root_stat = _lstat(root, "allowed root")
    _reject_symlink(root, root_stat)
    _reject_symlink_components(root)
    canonical = root.resolve(strict=True)
    if not stat.S_ISDIR(_lstat(canonical, "allowed root").st_mode):
        raise PathSafetyError(f"allowed root must be a directory: {canonical}")
    return canonical


def _containing_root(path: Path, roots: tuple[Path, ...]) -> Path:
    containing = [root for root in roots if _strictly_below(path, root)]
    if not containing:
        raise PathSafetyError(f"target is outside allowed roots: {path}")
    return max(containing, key=lambda root: len(root.parts))


def _reject_broad_target(path: Path) -> None:
    if path == Path("/") or path == Path.home().resolve():
        raise PathSafetyError(f"broad cleanup target is not allowed: {path}")


def _identity_from_path(requested: str, canonical: Path) -> PathIdentity:
    target_stat = _lstat(canonical, "target")
    _reject_symlink(canonical, target_stat)
    _reject_symlink_components(canonical)
    kind = _kind(canonical, target_stat)
    logical_bytes, descendants = _tree_snapshot_path(canonical, target_stat, ".")
    return _make_identity(requested, str(canonical), kind, target_stat, logical_bytes, descendants)


def _identity_from_fd(requested: str, canonical: Path, target_fd: int) -> PathIdentity:
    target_stat = os.fstat(target_fd)
    kind = _kind(canonical, target_stat)
    logical_bytes, descendants = _tree_snapshot_fd(target_fd, target_stat, ".")
    return _make_identity(requested, str(canonical), kind, target_stat, logical_bytes, descendants)


def _make_identity(
    requested: str,
    canonical: str,
    kind: str,
    target_stat: os.stat_result,
    logical_bytes: int,
    descendants: tuple[str, ...],
) -> PathIdentity:
    return PathIdentity(
        requested=requested,
        canonical=canonical,
        kind=kind,
        owner_uid=target_stat.st_uid,
        device=target_stat.st_dev,
        inode=target_stat.st_ino,
        mtime_ns=target_stat.st_mtime_ns,
        logical_bytes=logical_bytes,
        fingerprint=_fingerprint(canonical, kind, target_stat, logical_bytes, descendants),
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


def _tree_snapshot_path(
    path: Path, path_stat: os.stat_result, relative: str
) -> tuple[int, tuple[str, ...]]:
    if _kind(path, path_stat) == "file":
        return path_stat.st_size, ()
    total = 0
    records: list[str] = []
    try:
        with os.scandir(path) as entries:
            for entry in sorted(entries, key=lambda item: item.name):
                entry_path = Path(entry.path)
                entry_stat = entry.stat(follow_symlinks=False)
                if entry.is_symlink():
                    raise PathSafetyError(f"symlinks are not allowed: {entry_path}")
                entry_kind = _kind(entry_path, entry_stat)
                child_relative = f"{relative}/{entry.name}"
                child_bytes, child_records = _tree_snapshot_path(
                    entry_path, entry_stat, child_relative
                )
                total += child_bytes
                records.append(_descendant_record(child_relative, entry_kind, entry_stat))
                records.extend(child_records)
    except OSError as error:
        raise PathSafetyError(f"cannot inspect directory contents: {path}") from error
    return total, tuple(records)


def _tree_snapshot_fd(
    directory_fd: int, directory_stat: os.stat_result, relative: str
) -> tuple[int, tuple[str, ...]]:
    if _kind(Path(relative), directory_stat) == "file":
        return directory_stat.st_size, ()
    total = 0
    records: list[str] = []
    try:
        with os.scandir(directory_fd) as entries:
            for entry in sorted(entries, key=lambda item: item.name):
                entry_stat = entry.stat(follow_symlinks=False)
                if entry.is_symlink():
                    raise PathSafetyError(f"symlinks are not allowed: {entry.name}")
                entry_kind = _kind(Path(entry.name), entry_stat)
                child_relative = f"{relative}/{entry.name}"
                if entry_kind == "directory":
                    child_fd = _open_at(entry.name, directory_fd, directory=True)
                    try:
                        child_stat = os.fstat(child_fd)
                        _require_same_stat(entry_stat, child_stat, entry.name)
                        child_bytes, child_records = _tree_snapshot_fd(
                            child_fd, child_stat, child_relative
                        )
                    finally:
                        os.close(child_fd)
                else:
                    child_bytes, child_records = entry_stat.st_size, ()
                total += child_bytes
                records.append(_descendant_record(child_relative, entry_kind, entry_stat))
                records.extend(child_records)
    except OSError as error:
        raise PathSafetyError("cannot inspect directory descriptor") from error
    return total, tuple(records)


def _descendant_record(relative: str, kind: str, path_stat: os.stat_result) -> str:
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


def _open_target_beneath(root: Path, target: Path) -> _OpenedTarget | None:
    relative = target.relative_to(root)
    parent_fd = _open_absolute_directory(root)
    try:
        for part in relative.parts[:-1]:
            child_fd = _open_at(part, parent_fd, directory=True)
            os.close(parent_fd)
            parent_fd = child_fd
        name = relative.parts[-1]
        try:
            target_stat = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            os.close(parent_fd)
            return None
        if stat.S_ISLNK(target_stat.st_mode):
            raise PathSafetyError(f"symlinks are not allowed: {target}")
        kind = _kind(target, target_stat)
        target_fd = _open_at(name, parent_fd, directory=kind == "directory")
        try:
            _require_same_stat(target_stat, os.fstat(target_fd), str(target))
        except BaseException:
            os.close(target_fd)
            raise
        return _OpenedTarget(parent_fd, target_fd, name, kind)
    except BaseException:
        os.close(parent_fd)
        raise


def _open_absolute_directory(path: Path) -> int:
    directory_fd = os.open("/", _open_flags(directory=True))
    try:
        for part in path.parts[1:]:
            child_fd = _open_at(part, directory_fd, directory=True)
            os.close(directory_fd)
            directory_fd = child_fd
        return directory_fd
    except BaseException:
        os.close(directory_fd)
        raise


def _open_at(name: str, parent_fd: int, *, directory: bool) -> int:
    try:
        return os.open(name, _open_flags(directory=directory), dir_fd=parent_fd)
    except OSError as error:
        raise PathSafetyError(f"cannot safely open path component: {name}") from error


def _open_flags(*, directory: bool) -> int:
    if not hasattr(os, "O_NOFOLLOW"):
        raise PathSafetyError("this platform does not support O_NOFOLLOW")
    flags = os.O_RDONLY | os.O_NOFOLLOW
    if directory:
        flags |= os.O_DIRECTORY
    return flags


def _require_same_stat(
    expected: os.stat_result, current: os.stat_result, label: str
) -> None:
    if (
        expected.st_dev,
        expected.st_ino,
        stat.S_IFMT(expected.st_mode),
        expected.st_uid,
        expected.st_mtime_ns,
        expected.st_size,
    ) != (
        current.st_dev,
        current.st_ino,
        stat.S_IFMT(current.st_mode),
        current.st_uid,
        current.st_mtime_ns,
        current.st_size,
    ):
        raise PathSafetyError(f"path changed while opening: {label}")


def _unlink_exact(parent_fd: int, name: str, target_fd: int) -> None:
    _require_same_stat(os.fstat(target_fd), _stat_at(parent_fd, name), name)
    try:
        os.unlink(name, dir_fd=parent_fd)
    except OSError as error:
        raise PathSafetyError(f"cannot remove file: {name}") from error


def _remove_directory_exact(parent_fd: int, name: str, directory_fd: int) -> None:
    try:
        with os.scandir(directory_fd) as entries:
            for entry in sorted(entries, key=lambda item: item.name):
                entry_stat = entry.stat(follow_symlinks=False)
                if entry.is_symlink():
                    raise PathSafetyError(f"symlinks are not allowed: {entry.name}")
                entry_kind = _kind(Path(entry.name), entry_stat)
                child_fd = _open_at(entry.name, directory_fd, directory=entry_kind == "directory")
                try:
                    _require_same_stat(entry_stat, os.fstat(child_fd), entry.name)
                    if entry_kind == "directory":
                        _remove_directory_exact(directory_fd, entry.name, child_fd)
                    else:
                        _unlink_exact(directory_fd, entry.name, child_fd)
                finally:
                    os.close(child_fd)
        _require_same_stat(os.fstat(directory_fd), _stat_at(parent_fd, name), name)
        os.rmdir(name, dir_fd=parent_fd)
    except OSError as error:
        raise PathSafetyError(f"cannot remove directory: {name}") from error


def _stat_at(parent_fd: int, name: str) -> os.stat_result:
    try:
        current = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
    except OSError as error:
        raise PathSafetyError(f"cannot inspect path component: {name}") from error
    if stat.S_ISLNK(current.st_mode):
        raise PathSafetyError(f"symlinks are not allowed: {name}")
    return current
