"""One-issue AI repair with verification and automatic rollback."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Literal

from ..fixer import verify_clean_git
from ..models import ScanResult
from ..repair_report import RepairReport, command_report, write_repair_report
from ..scanner import scan
from .errors import PatchValidationError, VerificationError
from .models import BehavioralContract, PatchProposal, PatchRequest, SemanticFinding, Severity
from .patching import (
    MIN_PATCH_CONFIDENCE,
    PreparedPatch,
    apply_patch,
    prepare_patch,
    render_patch_diff,
    rollback_patch,
)
from .prompts import DEFAULT_PROMPT_VARIANT
from .provider import LLMProvider
from .workflow import analyze_repository

FixStatus = Literal["no_candidate", "preview", "dry_run", "kept", "rolled_back"]
SEVERITY_ORDER = {
    Severity.CRITICAL: 4,
    Severity.HIGH: 3,
    Severity.MEDIUM: 2,
    Severity.LOW: 1,
}


@dataclass(frozen=True)
class AIFixOutcome:
    """User-facing state from one constrained repair attempt."""

    status: FixStatus
    finding: SemanticFinding | None = None
    proposal: PatchProposal | None = None
    diff: str = ""
    verification: str = ""
    behavioral_contract: BehavioralContract | None = None


def select_fix_candidate(findings: tuple[SemanticFinding, ...]) -> SemanticFinding | None:
    """Choose at most one high-confidence issue by severity then confidence."""
    eligible = [item for item in findings if item.confidence >= MIN_PATCH_CONFIDENCE]
    if not eligible:
        return None
    return max(eligible, key=lambda item: (SEVERITY_ORDER[item.severity], item.confidence, item.id))


def _verification_passed(before: ScanResult, after: ScanResult) -> tuple[bool, str]:
    if not before.commands:
        return False, "No test or lint commands were available for verification."
    expected = [(item.name, item.command) for item in before.commands]
    actual = [(item.name, item.command) for item in after.commands]
    if actual != expected:
        return False, "The verification command set changed after the patch."
    failures = [item.name for item in after.commands if not item.passed]
    if failures:
        return False, "Verification failed: " + ", ".join(failures) + "."
    if after.deterministic_score < before.deterministic_score:
        return False, "Deterministic health score regressed after the patch."
    return True, "All discovered tests and linters passed without score regression."


def _finding_data(finding: SemanticFinding) -> dict:
    value = asdict(finding)
    value["severity"] = finding.severity.value
    return value


def _rollback_after_report(
    prepared: PreparedPatch,
    report: RepairReport,
    report_path: Path | None,
) -> None:
    """Persist attempted-patch evidence before restoring repository bytes."""
    report.rollback_attempted = True
    report.final_status = "verification_failed_pending_rollback"
    report_error: OSError | None = None
    try:
        write_repair_report(report_path, report)
    except OSError as error:
        report_error = error
    try:
        rollback_patch(prepared)
    except Exception:
        report.rollback_succeeded = False
        report.final_status = "rollback_failed"
        try:
            write_repair_report(report_path, report)
        except OSError:
            pass
        raise
    report.rollback_succeeded = True
    report.final_status = "rolled_back"
    write_repair_report(report_path, report)
    if report_error is not None:
        raise report_error


def execute_ai_fix(
    root: Path,
    provider: LLMProvider,
    *,
    timeout: int = 120,
    dry_run: bool = False,
    scan_function: Callable[[Path, int], ScanResult] = scan,
    trusted_execution: bool = False,
    task: str | None = None,
    prompt_variant: str = DEFAULT_PROMPT_VARIANT,
    report_path: Path | None = None,
) -> AIFixOutcome:
    """Preview one patch, or explicitly opt into applying and verifying it."""
    report = RepairReport(
        prompt_variant=prompt_variant,
        task_provided=bool(task and task.strip()),
    )
    root = root.resolve()
    if trusted_execution:
        verify_clean_git(root)
    baseline = (
        scan(root, timeout, verify=trusted_execution)
        if scan_function is scan
        else scan_function(root, timeout)
    )
    if trusted_execution and not baseline.commands:
        raise VerificationError(
            "AI fix requires at least one discovered test or lint command for verification."
        )
    write_repair_report(report_path, report)
    response, contexts = analyze_repository(baseline, provider, task=task)
    contract = response.behavioral_contract
    if contract is None:  # Defensive: analyze_repository always completes the contract.
        raise VerificationError("AI analysis did not produce a behavioral contract.")
    report.analysis_summary = (
        f"{len(response.findings)} validated finding(s): "
        + "; ".join(f"{item.id}: {item.title}" for item in response.findings)
        if response.findings
        else "No validated semantic findings were returned."
    )
    report.behavioral_contract = asdict(contract)
    finding = select_fix_candidate(response.findings)
    if finding is None:
        report.final_status = "no_candidate"
        write_repair_report(report_path, report)
        return AIFixOutcome("no_candidate", behavioral_contract=contract)
    report.selected_finding = _finding_data(finding)
    context_by_path = {item.path: item for item in contexts}
    context = context_by_path[finding.file]
    proposal = provider.generate_patch(PatchRequest(finding, context, contract))
    if proposal.file != finding.file:
        raise PatchValidationError("AI patch file does not match the selected finding.")
    prepared: PreparedPatch = prepare_patch(root, proposal, expected_sha256=context.sha256)
    preview = render_patch_diff(prepared)
    report.patch = {
        "file": proposal.file,
        "reason": proposal.reason,
        "confidence": proposal.confidence,
        "diff": preview,
    }
    if dry_run:
        report.final_status = "dry_run"
        write_repair_report(report_path, report)
        return AIFixOutcome("dry_run", finding, proposal, preview, behavioral_contract=contract)
    if not trusted_execution:
        report.final_status = "safe_preview"
        write_repair_report(report_path, report)
        return AIFixOutcome("preview", finding, proposal, preview, behavioral_contract=contract)

    apply_patch(prepared)
    report.patch_applied = True
    report.final_status = "patch_applied_pending_verification"
    try:
        write_repair_report(report_path, report)
    except OSError:
        rollback_patch(prepared)
        raise
    try:
        after = (
            scan(root, timeout, verify=True)
            if scan_function is scan
            else scan_function(root, timeout)
        )
        passed, verification = _verification_passed(baseline, after)
    except Exception as error:
        verification = f"Verification could not complete: {error}"
        report.verification = {"summary": verification, "commands": []}
        _rollback_after_report(prepared, report, report_path)
        return AIFixOutcome(
            "rolled_back",
            finding,
            proposal,
            preview,
            verification,
            contract,
        )
    report.verification = {
        "summary": verification,
        "commands": [command_report(item) for item in after.commands],
    }
    if passed:
        report.final_status = "kept"
        write_repair_report(report_path, report)
        return AIFixOutcome("kept", finding, proposal, preview, verification, contract)
    _rollback_after_report(prepared, report, report_path)
    return AIFixOutcome("rolled_back", finding, proposal, preview, verification, contract)
