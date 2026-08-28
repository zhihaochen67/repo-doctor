"""AI repair orchestration whose mutation and verification boundary is ToolHub."""

from __future__ import annotations

import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ..backends import MCPToolBackend, MutationConflictError
from ..detector import discover_commands
from ..repair_sessions import (
    RepairPhase,
    RepairSession,
    VerificationPlan,
    new_repair_session,
    record_patch_conflict,
    record_patch_request,
    resume_repair_session,
    save_repair_session,
)
from ..scanner import scan
from ..security import redact_sensitive_text
from .errors import PatchValidationError, VerificationError
from .fixer import select_fix_candidate
from .models import FileContext, PatchRequest
from .patching import prepare_patch_from_content, render_patch_diff
from .provider import LLMProvider
from .workflow import analyze_repository


@dataclass(frozen=True)
class MCPFixOutcome:
    status: str
    session: RepairSession | None = None
    diff: str = ""


def execute_mcp_ai_fix(
    root: Path,
    provider: LLMProvider,
    *,
    timeout: int = 120,
    dry_run: bool = False,
    backend_factory: Callable[[Path], MCPToolBackend] = MCPToolBackend,
    task: str | None = None,
) -> MCPFixOutcome:
    """Diagnose one repair, then submit its exact patch to ToolHub.

    No local patch application, local rollback, verification subprocess, or
    local Git subprocess is reachable from this function.
    """
    root = root.resolve()
    diagnosis_backend = backend_factory(root)
    baseline = scan(root, timeout, backend=diagnosis_backend, verify=False)
    verification_plan = tuple(
        VerificationPlan(name, command)
        for name, command in discover_commands(root, baseline.technologies)
    )
    if not verification_plan:
        raise VerificationError(
            "AI fix requires at least one discovered test or lint command for verification."
        )

    response, contexts = analyze_repository(baseline, provider, task=task)
    contract = response.behavioral_contract
    if contract is None:  # Defensive: analyze_repository always completes the contract.
        raise VerificationError("AI analysis did not produce a behavioral contract.")
    finding = select_fix_candidate(response.findings)
    if finding is None:
        return MCPFixOutcome("no_candidate")
    context_by_path = {item.path: item for item in contexts}
    if finding.file not in context_by_path:
        raise PatchValidationError("Selected AI finding has no validated file context.")

    with backend_factory(root) as backend:
        status = backend.git_status()
        if not status.clean:
            raise ValueError("Fix mode requires a clean worktree; commit or stash changes first.")
        target = backend.read_file(finding.file)
        patch_context = FileContext(
            target.path,
            redact_sensitive_text(target.content),
            target.sha256,
        )
        request = PatchRequest(finding, patch_context, contract)
        proposal = provider.generate_patch(request)
        if proposal.file != finding.file:
            raise PatchValidationError("AI patch file does not match the selected finding.")
        prepared = prepare_patch_from_content(
            root,
            proposal,
            content=target.content,
            expected_sha256=target.sha256,
        )
        preview = render_patch_diff(prepared)
        if dry_run:
            return MCPFixOutcome("dry_run", diff=preview)

        session = new_repair_session(
            root,
            finding_id=finding.id,
            finding_title=finding.title,
            target_file=prepared.relative_path,
            expected_hash=target.sha256,
            proposed_hash=hashlib.sha256(prepared.updated_bytes).hexdigest(),
            verification_plan=verification_plan,
        )
        try:
            mutation = backend.apply_patch(
                prepared.relative_path,
                preview,
                target.sha256,
            )
        except MutationConflictError as error:
            record_patch_conflict(session, error)
            save_repair_session(session)
            return MCPFixOutcome(RepairPhase.PATCH_CONFLICT.value, session, preview)
        record_patch_request(session, mutation)
        save_repair_session(session)

    if session.phase is RepairPhase.PATCH_APPLIED:
        resume_repair_session(session, timeout=timeout, backend_factory=backend_factory)
    return MCPFixOutcome(session.phase.value, session, preview)
