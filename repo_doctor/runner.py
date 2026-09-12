"""Explicitly opted-in host subprocess execution."""

import subprocess
import sys
import time
from pathlib import Path

from .models import CommandResult
from .security import verification_environment


def _output_text(value: str | bytes | None) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value or ""


def run_command(
    name: str, command: tuple[str, ...], cwd: Path, timeout: int = 120
) -> CommandResult:
    """Run an argument-vector command without a shell and capture all output."""
    started = time.monotonic()
    env = verification_environment()
    actual_command = command
    try:
        try:
            process = subprocess.run(
                actual_command,
                cwd=cwd,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
            )
        except FileNotFoundError:
            if command[0] not in {"pytest", "ruff"}:
                raise
            actual_command = (sys.executable, "-m", *command)
            process = subprocess.run(
                actual_command,
                cwd=cwd,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                check=False,
            )
        return CommandResult(
            name,
            actual_command,
            process.returncode,
            process.stdout,
            process.stderr,
            time.monotonic() - started,
        )
    except FileNotFoundError:
        return CommandResult(
            name,
            actual_command,
            127,
            "",
            f"Command not found: {command[0]}",
            time.monotonic() - started,
        )
    except subprocess.TimeoutExpired as error:
        return CommandResult(
            name,
            actual_command,
            124,
            _output_text(error.stdout),
            _output_text(error.stderr),
            time.monotonic() - started,
            True,
        )
