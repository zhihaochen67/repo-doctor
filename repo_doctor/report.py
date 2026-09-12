"""Markdown report rendering."""

from .ai.models import SemanticFinding
from .analyzer import AI_CONFIDENCE_THRESHOLD, AI_SCORE_PENALTIES
from .models import ScanResult
from .security import redact_sensitive_text


def _results(result: ScanResult, kind: str) -> str:
    items = result.commands
    selected = [item for item in items if kind.lower() in item.name.lower()]
    if not selected:
        planned = [item for item in result.verification_plan if kind.lower() in item[0].lower()]
        if planned:
            commands = ", ".join(f"`{' '.join(command)}`" for _, command in planned)
            return (
                "Discovered but intentionally not run in safe mode: "
                f"{commands}. Use `--trusted-execution` to run repository commands."
            )
        return "No commands discovered."
    blocks = []
    for item in selected:
        if item.approval_required:
            status = "APPROVAL REQUIRED"
            approval = f"Request ID: {item.request_id or 'unknown'}\n{item.message}".strip()
        elif not item.executed:
            status = (
                "UNAVAILABLE"
                if item.error_code == "REQUEST_NOT_FOUND"
                else item.approval_status or item.toolhub_outcome or "UNAVAILABLE"
            )
            approval = f"Request ID: {item.request_id or 'unknown'}\n{item.message}".strip()
        else:
            status = "PASS" if item.passed else "FAIL"
            approval = ""
        combined_output = "\n".join(
            value for value in (item.stdout, item.stderr, approval) if value
        )
        output = redact_sensitive_text(combined_output.strip()[-4000:]) or "(no output)"
        heading = f"### {item.name}: {status}"
        outcome = f"exit {item.exit_code}" if item.executed else "not executed"
        trace = f", trace {item.trace_id}" if item.trace_id else ""
        detail = f"`{' '.join(item.command)}` - {item.duration:.2f}s, {outcome}{trace}"
        blocks.append(f"{heading}\n\n{detail}\n\n```text\n{output}\n```")
    return "\n\n".join(blocks)


def _ai_finding(item: SemanticFinding, index: int) -> str:
    lines = (
        str(item.line_start)
        if item.line_start == item.line_end
        else f"{item.line_start}-{item.line_end}"
    )
    return f"""### Finding {index}: {item.title}

- Severity: {item.severity.value.title()}
- Confidence: {item.confidence:.2f}
- Category: {item.category}
- File: `{item.file}`
- Lines: {lines}

Problem:
{item.explanation}

Evidence:
{item.evidence}

Suggested fix:
{item.suggested_fix}"""


def _ai_analysis(result: ScanResult) -> str:
    if not result.ai_requested:
        return "AI Semantic Analysis: Not requested."
    if result.ai_error:
        return result.ai_error
    if not result.ai_findings:
        return "AI semantic analysis completed; no concrete findings were returned."
    return "\n\n".join(_ai_finding(item, index) for index, item in enumerate(result.ai_findings, 1))


def _score_explanation(result: ScanResult) -> str:
    rules = ", ".join(
        f"{severity.value}={penalty}" for severity, penalty in AI_SCORE_PENALTIES.items()
    )
    ai_penalty = result.deterministic_score - result.score
    return (
        f"Deterministic score: **{result.deterministic_score}/100**. "
        f"Validated AI findings at confidence >= {AI_CONFIDENCE_THRESHOLD:.2f} apply fixed "
        f"penalties ({rules}); applied AI penalty: **{ai_penalty}**."
    )


def render_report(result: ScanResult) -> str:
    """Render the complete health report as Markdown."""
    recs = result.potential_bugs + result.maintainability_issues
    recommendations = (
        "\n".join(f"{i}. {value}" for i, value in enumerate(recs, 1))
        or "1. Keep dependencies and verification tools current."
    )
    inspected = ", ".join(result.inspected_files) or "none"
    return f"""# Repo Doctor Health Report

## Project Overview

Analyzed `{result.path.name}` locally. Inspected configuration: {inspected}.

## Detected Technology Stack

{", ".join(result.technologies) or "Unknown"}

## Repository Statistics

- Files: {result.files}
- Text lines: {result.lines}

## Test Results

{_results(result, "test")}

## Lint Results

{_results(result, "lint")}

## Potential Bugs

{chr(10).join(f"- {x}" for x in result.potential_bugs) or "- None detected."}

## Maintainability Issues

{chr(10).join(f"- {x}" for x in result.maintainability_issues) or "- None detected."}

## AI Semantic Analysis

{_ai_analysis(result)}

## Prioritized Recommendations

{recommendations}

## Health Score (0-100)

**{result.score}/100**

{_score_explanation(result)}
"""
