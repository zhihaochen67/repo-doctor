"""Shared, immutable data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .ai.models import SemanticFinding


@dataclass(frozen=True)
class CommandResult:
    """Captured result of a verification command."""

    name: str
    command: tuple[str, ...]
    exit_code: int
    stdout: str
    stderr: str
    duration: float
    timed_out: bool = False
    approval_required: bool = False
    request_id: str | None = None
    approval_status: str | None = None
    message: str = ""
    executed: bool = True
    trace_id: str | None = None
    toolhub_outcome: str | None = None
    resume_tool: str | None = None
    expires_at: str | None = None
    error_code: str | None = None
    error_retryable: bool | None = None

    @property
    def passed(self) -> bool:
        return self.executed and self.exit_code == 0 and not self.timed_out


@dataclass(frozen=True)
class FileReadResult:
    """One UTF-8 file returned by a tool backend."""

    path: str
    size: int
    sha256: str
    content: str


@dataclass(frozen=True)
class PatchMutationResult:
    """Structured result of a ToolHub filesystem patch request or execution."""

    path: str
    executed: bool
    changed: bool = False
    additions: int = 0
    deletions: int = 0
    bytes_before: int = 0
    bytes_after: int = 0
    previous_hash: str | None = None
    new_hash: str | None = None
    trace_id: str | None = None
    request_id: str | None = None
    approval_status: str | None = None
    message: str = ""
    toolhub_outcome: str | None = None
    resume_tool: str | None = None
    expires_at: str | None = None
    error_code: str | None = None
    error_retryable: bool | None = None

    @property
    def approval_required(self) -> bool:
        return self.toolhub_outcome == "APPROVAL_REQUIRED"


@dataclass(frozen=True)
class GitStatusEntry:
    """One porcelain Git status entry."""

    code: str
    path: str


@dataclass(frozen=True)
class GitStatusResult:
    """Structured Git worktree status."""

    path: str
    branch: str | None
    clean: bool
    entries: tuple[GitStatusEntry, ...]
    raw: str


@dataclass(frozen=True)
class GitDiffResult:
    """Structured Git diff output."""

    path: str | None
    staged: bool
    additions: int | None
    deletions: int | None
    binary: bool
    raw: str


@dataclass
class ScanResult:
    """All evidence collected during a scan."""

    path: Path
    technologies: list[str]
    files: int
    lines: int
    inspected_files: list[str]
    commands: list[CommandResult] = field(default_factory=list)
    potential_bugs: list[str] = field(default_factory=list)
    maintainability_issues: list[str] = field(default_factory=list)
    deterministic_score: int = 100
    score: int = 100
    ai_requested: bool = False
    ai_findings: list[SemanticFinding] = field(default_factory=list)
    ai_error: str | None = None
    ai_context_files: list[str] = field(default_factory=list)
