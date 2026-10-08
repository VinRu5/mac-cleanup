"""Small, argv-only process boundary for capability-aware cleanup tools."""

from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import subprocess
import time
from collections.abc import Sequence


class CommandTimeout(RuntimeError):
    """Describes a process which exceeded its caller-supplied timeout."""


@dataclass(frozen=True)
class CommandResult:
    argv: tuple[str, ...]
    exit_code: int | None
    stdout: str
    stderr: str
    duration_seconds: float
    timed_out: bool = False
    mutation: bool = False
    available: bool = True
    disallowed: bool = False
    disallowed_reason: str | None = None

    @property
    def returncode(self) -> int | None:
        return self.exit_code

    @property
    def duration(self) -> float:
        return self.duration_seconds


class ToolResolver:
    """Resolve an executable through the user's normal PATH."""

    def resolve(self, name: str) -> Path | None:
        resolved = shutil.which(name)
        return Path(resolved) if resolved is not None else None


class ProcessRunner:
    def __init__(self, resolver: ToolResolver | None = None) -> None:
        self._resolver = resolver or ToolResolver()

    def run(
        self,
        argv: Sequence[str],
        timeout_seconds: float,
        mutation: bool = False,
    ) -> CommandResult:
        if isinstance(argv, (str, bytes)):
            raise TypeError("commands must be provided as an argv sequence")
        command = tuple(argv)
        if not command or any(not isinstance(item, str) or not item for item in command):
            raise TypeError("argv must be a non-empty sequence of non-empty strings")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")

        forbidden = _disallowed_reason(command, mutation)
        if forbidden is not None:
            return CommandResult(
                argv=command, exit_code=None, stdout="", stderr=forbidden,
                duration_seconds=0.0, mutation=mutation, disallowed=True,
                disallowed_reason=forbidden,
            )

        if self._resolver.resolve(command[0]) is None:
            return CommandResult(
                argv=command, exit_code=None, stdout="",
                stderr=f"executable unavailable: {command[0]}",
                duration_seconds=0.0, mutation=mutation, available=False,
            )

        started = time.monotonic()
        try:
            completed = subprocess.run(
                command,
                shell=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired as error:
            return CommandResult(
                argv=command, exit_code=None,
                stdout=_output_text(error.stdout), stderr=_output_text(error.stderr),
                duration_seconds=time.monotonic() - started, timed_out=True,
                mutation=mutation,
            )
        return CommandResult(
            argv=command, exit_code=completed.returncode,
            stdout=completed.stdout, stderr=completed.stderr,
            duration_seconds=time.monotonic() - started, mutation=mutation,
        )


def _output_text(value: str | bytes | None) -> str:
    if value is None:
        return ""
    return value.decode(errors="replace") if isinstance(value, bytes) else value


def _disallowed_reason(argv: tuple[str, ...], mutation: bool) -> str | None:
    executable = os.path.basename(argv[0])
    args = tuple(item.lower() for item in argv[1:])
    if executable == "open":
        return "open is disallowed during scans"
    if executable == "adb" and args[:1] == ("devices",):
        return "adb devices is disallowed during scans"
    package_tools = {"brew", "npm", "pnpm", "yarn", "pip", "pip3"}
    package_actions = {"cleanup", "autoremove", "prune", "remove", "uninstall"}
    if executable in package_tools and package_actions.intersection(args):
        if "--dry-run" not in args and "--dryrun" not in args:
            return "non-dry-run package cleanup is disallowed during scans"
    return None
