"""The fixed built-in cleanup module registry."""

from __future__ import annotations

from .base import CleanupModule
from .user_caches import UserCachesModule


def registered_modules() -> tuple[CleanupModule, ...]:
    """Return the deterministic built-in registry; never load arbitrary code."""
    modules: tuple[CleanupModule, ...] = (UserCachesModule(),)
    return tuple(sorted(modules, key=lambda module: module.id))
