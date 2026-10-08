"""Small, argv-only process boundary for capability-aware cleanup tools."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import os
from pathlib import Path
import shutil
import subprocess
import time
from collections.abc import Sequence


class CommandTimeout(RuntimeError):
    """Describes a process which exceeded its caller-supplied timeout."""


class OperationMode(str, Enum):
    SCAN = "scan"
    APPROVED_MUTATION = "approved_mutation"


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
        mode: OperationMode | str | None = None,
    ) -> CommandResult:
        if isinstance(argv, (str, bytes)):
            raise TypeError("commands must be provided as an argv sequence")
        command = tuple(argv)
        if not command or any(not isinstance(item, str) or not item for item in command):
            raise TypeError("argv must be a non-empty sequence of non-empty strings")
        if timeout_seconds <= 0:
            raise ValueError("timeout_seconds must be positive")

        operation_mode = _mode(mode, mutation)
        mutation = operation_mode is OperationMode.APPROVED_MUTATION
        forbidden = _disallowed_reason(command, operation_mode)
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


def _mode(mode: OperationMode | str | None, mutation: bool) -> OperationMode:
    if mode is None:
        return OperationMode.APPROVED_MUTATION if mutation else OperationMode.SCAN
    try:
        return OperationMode(mode)
    except ValueError as error:
        raise ValueError(f"unsupported operation mode: {mode}") from error


def _unwrap(argv: tuple[str, ...]) -> tuple[str, tuple[str, ...]]:
    """Return the real executable and args for common command wrappers."""
    index = 0
    while index < len(argv):
        name = os.path.basename(argv[index])
        if name == "env":
            index += 1
            while index < len(argv):
                option = argv[index]
                if "=" in option:
                    index += 1
                elif option in {"-u", "--unset", "-C", "--chdir"}:
                    index += 2
                elif option in {"-i", "--ignore-environment", "-0"}:
                    index += 1
                elif option.startswith("-"):
                    return "", ()
                else:
                    break
            continue
        if name in {"sudo", "command", "exec"}:
            index += 1
            if name == "sudo":
                while index < len(argv):
                    option = argv[index]
                    if option in {"-u", "--user", "-g", "--group", "-h", "--host", "-D", "--chdir"}:
                        index += 2
                    elif option in {"-n", "--non-interactive", "-E", "--preserve-env"}:
                        index += 1
                    elif option.startswith("-"):
                        return "", ()
                    else:
                        break
            else:
                while index < len(argv):
                    option = argv[index]
                    if name == "command" and option == "-p":
                        index += 1
                    elif name == "exec" and option in {"-a", "--argv0"}:
                        index += 2
                    elif name == "exec" and option in {"-c", "-l"}:
                        index += 1
                    elif option.startswith("-"):
                        return "", ()
                    else:
                        break
            continue
        break
    if index >= len(argv):
        return "", ()
    return os.path.basename(argv[index]), argv[index + 1:]


def _disallowed_reason(argv: tuple[str, ...], mode: OperationMode) -> str | None:
    executable, raw_args = _unwrap(argv)
    if not executable:
        return "unsupported command wrapper is disallowed during scans"
    args = tuple(item.lower() for item in raw_args)
    if mode is not OperationMode.SCAN:
        return None
    if executable == "open":
        return "open is disallowed during scans"
    if executable == "adb":
        # adb accepts global options before its subcommand.
        if "devices" in args:
            return "adb devices is disallowed during scans"
    package_tools = {"brew", "npm", "pnpm", "yarn", "pip", "pip3"}
    if executable not in package_tools:
        return None
    if _package_cleanup(executable, args) and not _explicit_dry_run(args):
        return "non-dry-run package cleanup is disallowed during scans"
    if not _package_scan_allowed(executable, args):
        return "unrecognized package command is disallowed during scans"
    return None


def _explicit_dry_run(args: tuple[str, ...]) -> bool:
    return "--dry-run" in args or "--dryrun" in args


def _package_cleanup(tool: str, args: tuple[str, ...]) -> bool:
    """Conservative package cleanup recognition; unknown actions are not blocked."""
    if tool == "brew":
        return "cleanup" in args
    if tool in {"npm", "pnpm"}:
        return args[:2] == ("cache", "clean")
    if tool == "yarn":
        return args[:2] == ("cache", "clean")
    if tool in {"pip", "pip3"}:
        return args[:2] == ("cache", "purge")
    return False


def _package_scan_allowed(tool: str, args: tuple[str, ...]) -> bool:
    if _explicit_dry_run(args):
        return True
    if tool == "brew":
        return args[:1] in (("--version",), ("list",), ("info",))
    if tool in {"npm", "pnpm"}:
        return args[:2] in (("cache", "verify"), ("--version",), ("-v",))
    if tool == "yarn":
        return args[:2] in (("cache", "dir"), ("cache", "list"), ("--version",))
    if tool in {"pip", "pip3"}:
        return args[:2] in (("cache", "dir"), ("cache", "list"), ("--version",))
    return False
