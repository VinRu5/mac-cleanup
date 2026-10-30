"""Canonical and atomic JSON persistence helpers."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
import stat
from typing import Any


def canonical_bytes(value: object) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def atomic_write_json(path: str | os.PathLike[str], value: object) -> None:
    destination = Path(path)
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=f".{destination.name}.", dir=destination.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(canonical_bytes(value))
            handle.flush()
            os.fsync(handle.fileno())
            metadata = os.fstat(handle.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != os.getuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
            ):
                raise OSError("temporary JSON metadata is unsafe")
        os.replace(temporary, destination)
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        directory_fd = os.open(destination.parent, flags)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        try:
            os.unlink(temporary)
        except FileNotFoundError:
            pass
        raise


def read_json(path: str | os.PathLike[str]) -> dict[str, object]:
    with Path(path).open("r", encoding="utf-8") as handle:
        value: Any = json.load(handle)
    if not isinstance(value, dict):
        raise ValueError("JSON root must be an object")
    return value
