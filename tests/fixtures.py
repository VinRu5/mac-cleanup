"""Filesystem fixtures shared by mac-cleanup tests."""

from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
import tempfile
from typing import Iterator


@contextmanager
def fake_home() -> Iterator[Path]:
    """Yield a fake home containing caches and deliberately protected data."""
    with tempfile.TemporaryDirectory() as directory:
        home = Path(directory).resolve()
        _write(home / "Library" / "Caches" / "com.example.app" / "cache.bin", b"cache")
        _write(home / "Library" / "Caches" / "Codex" / "session.bin", b"session")
        _write(home / "Library" / "Caches" / "io.sentry" / "event.bin", b"event")
        _write(
            home / "Library" / "Application Support" / "com.example.app" / "config.json",
            b"{}",
        )
        _write(home / ".env", b"TOKEN=secret\n")
        _write(home / "project" / "pubspec.yaml", b"name: protected\n")
        yield home


def _write(path: Path, content: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)
