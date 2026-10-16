#!/usr/bin/env python3
"""Executable wrapper for the mac-cleanup CLI."""

def run() -> int:
    """Import the package only when the executable is invoked."""
    from mac_cleanup.cli import main

    return main()


if __name__ == "__main__":
    raise SystemExit(run())
