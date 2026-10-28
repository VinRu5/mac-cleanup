"""Read-only discovery of conservative, user-owned macOS cache candidates."""

from __future__ import annotations

import os
from pathlib import Path
import stat

from ..models import Issue, Risk, Severity, Target
from ..paths import PathIdentity, PathSafetyError, inspect_path
from .base import ScanContext, ScanResult


class UserCachesModule:
    """Inventory only immediate children of ``<home>/Library/Caches``."""

    id = "user-caches"
    _TARGET_PREFIX = f"{id}:"

    def detect(self, context: ScanContext) -> bool:
        """Detect a present non-symlink cache root, even when it is unreadable."""
        return _present_directory(self._cache_root(context))

    def fast_scan(self, context: ScanContext) -> ScanResult:
        """Inspect each immediate, non-Apple child of the fixed cache root."""
        root, issues = self._usable_root(context)
        if root is None:
            return ScanResult(issues=issues)
        names, scan_issue = _child_names(root)
        if scan_issue is not None:
            issues.append(scan_issue)
            return ScanResult(issues=tuple(issues))
        targets: list[Target] = []
        for name in names:
            target, issue = self._inspect_shallow_candidate(context, root, name)
            if target is not None:
                targets.append(target)
            if issue is not None:
                issues.append(issue)
        return ScanResult(targets=tuple(targets), issues=tuple(issues))

    def deep_scan(
        self, context: ScanContext, candidate_ids: tuple[str, ...]
    ) -> ScanResult:
        """Re-inspect selected cache children; identifiers cannot name paths."""
        root, issues = self._usable_root(context)
        if root is None:
            return ScanResult(issues=issues)
        names, scan_issue = _child_names(root)
        if scan_issue is not None:
            issues.append(scan_issue)
            return ScanResult(issues=tuple(issues))
        available_names = set(names)
        targets: list[Target] = []
        for candidate_id in sorted(set(candidate_ids)):
            name = self._candidate_name(candidate_id)
            if name is None or name not in available_names:
                continue
            target, issue = self._inspect_deep_candidate(context, root, name)
            if target is not None and target.logical_bytes >= context.deep_scan_threshold:
                targets.append(target)
            if issue is not None:
                issues.append(issue)
        return ScanResult(
            targets=tuple(targets),
            issues=tuple(issues),
            executable_target_ids=tuple(target.id for target in targets),
        )

    def _cache_root(self, context: ScanContext) -> Path:
        return context.home / "Library" / "Caches"

    def _usable_root(self, context: ScanContext) -> tuple[Path | None, list[Issue]]:
        root = self._cache_root(context)
        if _safe_directory(root):
            return root, []
        return None, [_warning("cache-root-unavailable", root)]

    def _candidate_name(self, candidate_id: str) -> str | None:
        if not candidate_id.startswith(self._TARGET_PREFIX):
            return None
        name = candidate_id.removeprefix(self._TARGET_PREFIX)
        if not _is_allowed_name(name):
            return None
        return name

    def _inspect_shallow_candidate(
        self, context: ScanContext, root: Path, name: str
    ) -> tuple[Target | None, Issue | None]:
        """Capture only immediate-entry metadata; never walk a candidate tree."""
        if not _is_allowed_name(name):
            return None, None
        candidate = root / name
        if not _safe_entry(candidate):
            return None, _warning("candidate-unavailable", candidate)
        try:
            candidate_stat = candidate.lstat()
        except OSError:
            return None, _warning("candidate-unavailable", candidate)
        if candidate_stat.st_uid != context.uid:
            return None, _warning("candidate-not-owned", candidate)
        return Target(
            id=f"{self._TARGET_PREFIX}{name}",
            path=str(candidate),
            kind=_kind(candidate_stat),
            risk=_risk_for(name),
            logical_bytes=candidate_stat.st_size,
        ), None

    def _inspect_deep_candidate(
        self, context: ScanContext, root: Path, name: str
    ) -> tuple[Target | None, Issue | None]:
        if not _is_allowed_name(name):
            return None, None
        candidate = root / name
        if not _safe_entry(candidate):
            return None, _warning("candidate-unavailable", candidate)
        try:
            identity = inspect_path(candidate, (root,))
        except PathSafetyError:
            return None, _warning("candidate-rejected", candidate)
        if identity.owner_uid != context.uid:
            return None, _warning("candidate-not-owned", candidate)
        return self._target(identity, name), None

    def _target(self, identity: PathIdentity, name: str) -> Target:
        return Target(
            id=f"{self._TARGET_PREFIX}{name}",
            path=identity.canonical,
            kind=identity.kind,
            risk=_risk_for(name),
            fingerprint=identity.fingerprint,
            logical_bytes=identity.logical_bytes,
        )


def _child_names(root: Path) -> tuple[tuple[str, ...], Issue | None]:
    try:
        with os.scandir(root) as entries:
            return tuple(sorted(entry.name for entry in entries if _is_allowed_name(entry.name))), None
    except OSError as error:
        return (), Issue(
            code="user-caches.cache-root-unavailable",
            severity=Severity.WARNING,
            message=f"Cannot enumerate approved cache root: {root}: {error}",
        )


def _safe_directory(path: Path) -> bool:
    try:
        path_stat = path.lstat()
    except OSError:
        return False
    return (
        _present_directory(path, metadata=path_stat)
        and os.access(path, os.R_OK | os.X_OK)
    )


def _present_directory(
    path: Path, *, metadata: os.stat_result | None = None
) -> bool:
    try:
        path_stat = metadata if metadata is not None else path.lstat()
    except OSError:
        return False
    return (
        stat.S_ISDIR(path_stat.st_mode)
        and not stat.S_ISLNK(path_stat.st_mode)
        and _has_no_symlink_components(path)
    )


def _safe_entry(path: Path) -> bool:
    try:
        path_stat = path.lstat()
    except OSError:
        return False
    if stat.S_ISLNK(path_stat.st_mode):
        return False
    if not (stat.S_ISDIR(path_stat.st_mode) or stat.S_ISREG(path_stat.st_mode)):
        return False
    access = os.R_OK | (os.X_OK if stat.S_ISDIR(path_stat.st_mode) else 0)
    return _has_no_symlink_components(path) and os.access(path, access)


def _kind(path_stat: os.stat_result) -> str:
    return "directory" if stat.S_ISDIR(path_stat.st_mode) else "file"


def _has_no_symlink_components(path: Path) -> bool:
    current = Path(path.anchor)
    try:
        for part in path.parts[1:]:
            current /= part
            if stat.S_ISLNK(current.lstat().st_mode):
                return False
    except OSError:
        return False
    return True


def _is_allowed_name(name: str) -> bool:
    return (
        bool(name)
        and name == Path(name).name
        and name not in {".", ".."}
        and not name.startswith("com.apple.")
    )


def _risk_for(name: str) -> Risk:
    lowered = name.casefold()
    if lowered == "codex" or lowered == "io.sentry" or lowered.startswith("io.sentry."):
        return Risk.REVIEW_REQUIRED
    return Risk.SAFE_REGENERABLE


def _warning(code: str, path: Path) -> Issue:
    return Issue(
        code=f"user-caches.{code}",
        severity=Severity.WARNING,
        message=f"Skipped unsafe or inaccessible cache path: {path}",
    )
