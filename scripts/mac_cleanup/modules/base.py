"""Stable contracts shared by cleanup discovery modules."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Protocol

from ..models import Issue, Target
from ..process import ProcessRunner


@dataclass(frozen=True)
class ScanContext:
    """The bounded capabilities and limits available to one discovery pass."""

    home: Path
    uid: int
    runner: ProcessRunner
    deep_scan_threshold: int
    timeout_seconds: float

    def __post_init__(self) -> None:
        home = Path(self.home)
        if not home.is_absolute():
            raise ValueError("home must be absolute")
        if self.uid < 0:
            raise ValueError("uid must be non-negative")
        if self.deep_scan_threshold < 0:
            raise ValueError("deep_scan_threshold must be non-negative")
        if self.timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")
        object.__setattr__(self, "home", home)


@dataclass(frozen=True)
class ScanResult:
    """Immutable, deterministic output of one module scan pass."""

    targets: tuple[Target, ...] = field(default_factory=tuple)
    issues: tuple[Issue, ...] = field(default_factory=tuple)
    executable_target_ids: tuple[str, ...] = field(default_factory=tuple)

    def __post_init__(self) -> None:
        targets = tuple(sorted(self.targets, key=lambda target: target.id))
        executable_target_ids = tuple(sorted(set(self.executable_target_ids)))
        target_ids = {target.id for target in targets}
        if not set(executable_target_ids).issubset(target_ids):
            raise ValueError("executable target ids must be present in scan targets")
        object.__setattr__(self, "targets", targets)
        object.__setattr__(self, "issues", tuple(self.issues))
        object.__setattr__(self, "executable_target_ids", executable_target_ids)

    @property
    def executable_targets(self) -> tuple[Target, ...]:
        """Return only recursively inspected targets safe for later approval."""
        executable_ids = set(self.executable_target_ids)
        return tuple(target for target in self.targets if target.id in executable_ids)


class CleanupModule(Protocol):
    """A fixed, side-effect-free inventory module."""

    id: str

    def detect(self, context: ScanContext) -> bool:
        """Return whether this module has an eligible location to inspect."""

    def fast_scan(self, context: ScanContext) -> ScanResult:
        """Inventory fixed, immediately known candidate locations."""

    def deep_scan(
        self, context: ScanContext, candidate_ids: tuple[str, ...]
    ) -> ScanResult:
        """Re-inspect explicitly selected candidates without widening scope."""
