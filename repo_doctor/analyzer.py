"""Small, deterministic health analysis rules."""

from pathlib import Path

from .ai.models import Severity
from .models import ScanResult

AI_CONFIDENCE_THRESHOLD = 0.85
AI_SCORE_PENALTIES = {
    Severity.CRITICAL: 20,
    Severity.HIGH: 12,
    Severity.MEDIUM: 5,
    Severity.LOW: 0,
}

TEXT_PROBE_CHUNK_SIZE = 64 * 1024


def analyze(result: ScanResult) -> None:
    """Annotate and score collected evidence."""
    result.potential_bugs.clear()
    result.maintainability_issues.clear()
    if not any(name.lower().startswith("readme") for name in result.inspected_files):
        result.maintainability_issues.append("No README was found at the repository root.")
    if not result.technologies:
        result.maintainability_issues.append("No supported project manifest was detected.")
    approvals = [item for item in result.commands if item.approval_required]
    unavailable = [
        item for item in result.commands if not item.executed and not item.approval_required
    ]
    failed = [item for item in result.commands if item.executed and not item.passed]
    for item in approvals:
        result.potential_bugs.append(
            f"{item.name} requires ToolHub approval (request {item.request_id or 'unknown'})."
        )
    for item in failed:
        result.potential_bugs.append(f"{item.name} failed with exit code {item.exit_code}.")
    for item in unavailable:
        state = item.approval_status or item.toolhub_outcome or "UNKNOWN"
        result.potential_bugs.append(
            f"{item.name} could not run because ToolHub request "
            f"{item.request_id or 'unknown'} is {state}."
        )
    if not result.commands:
        result.maintainability_issues.append("No supported test or lint commands were discovered.")
    result.deterministic_score = max(
        0, 100 - 25 * len(failed) - 10 * len(result.maintainability_issues)
    )
    result.score = result.deterministic_score


def apply_ai_score(result: ScanResult) -> None:
    """Apply transparent, bounded penalties for validated high-confidence findings."""
    penalty = sum(
        AI_SCORE_PENALTIES[finding.severity]
        for finding in result.ai_findings
        if finding.confidence >= AI_CONFIDENCE_THRESHOLD
    )
    result.score = max(0, result.deterministic_score - penalty)


def text_files(root: Path):
    """Yield small regular-file candidates while skipping tool metadata."""
    ignored = {
        ".git",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".pytest_cache",
        ".ruff_cache",
        ".repo-doctor",
    }
    for path in root.rglob("*"):
        if (
            not path.is_symlink()
            and path.is_file()
            and not ignored.intersection(path.parts)
            and path.stat().st_size <= 1_000_000
        ):
            yield path


def is_utf8_text_file(path: Path) -> bool:
    """Return whether *path* satisfies Repo Doctor's strict text scanning policy.

    Decode failures mean that the file is intentionally outside the scanner's
    text domain. Filesystem failures deliberately propagate so disappearance,
    permission, and workspace problems are never mistaken for binary files.
    """
    try:
        with path.open(encoding="utf-8") as stream:
            while stream.read(TEXT_PROBE_CHUNK_SIZE):
                pass
    except UnicodeError:
        return False
    return True
