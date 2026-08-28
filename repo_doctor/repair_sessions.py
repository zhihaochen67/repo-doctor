"""Persistent multi-phase orchestration for MCP AI repair approvals."""

from __future__ import annotations

import json
import os
import secrets
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from .backends import MCPToolBackend, MutationConflictError
from .models import CommandResult, GitDiffResult, PatchMutationResult
from .security import redact_sensitive_text
from .sessions import (
    MAX_SESSION_BYTES,
    SessionError,
    encode_session_payload,
    find_session_file,
    session_file_path,
)
from .toolhub_contract import (
    ContractOutcome,
    RequestStatusResult,
    expected_resume_tool,
)

REPAIR_SESSION_SCHEMA_VERSION = 2
MAX_REPAIR_OUTPUT_CHARS = 4_000
MAX_REPAIR_COMMANDS = 32
MAX_REPAIR_OPERATIONS = 64


class RepairPhase(StrEnum):
    """Explicit MCP repair lifecycle recorded by Repo Doctor."""

    DIAGNOSED = "diagnosed"
    PATCH_PENDING = "patch_pending"
    PATCH_APPLIED = "patch_applied"
    VERIFICATION_PENDING = "verification_pending"
    VERIFIED_PASS = "verified_pass"
    PATCH_REJECTED = "patch_rejected"
    PATCH_EXPIRED = "patch_expired"
    PATCH_CONFLICT = "patch_conflict"
    VERIFICATION_FAILED = "verification_failed"
    VERIFICATION_REJECTED = "verification_rejected"
    VERIFICATION_EXPIRED = "verification_expired"
    ERROR = "error"


class RepairOperationKind(StrEnum):
    PATCH = "patch"
    VERIFICATION = "verification"


class RepairOperationStatus(StrEnum):
    PENDING = "pending"
    COMPLETED = "completed"
    FAILED = "failed"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CONSUMED = "consumed"
    CONFLICT = "conflict"
    REFUSED = "refused"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class VerificationPlan:
    name: str
    command: tuple[str, ...]


@dataclass
class RepairOperation:
    operation_id: str
    kind: RepairOperationKind
    status: RepairOperationStatus
    name: str
    request_id: str | None = None
    target_file: str | None = None
    expected_hash: str | None = None
    verification_index: int | None = None
    command: tuple[str, ...] = ()
    exit_code: int | None = None
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False
    toolhub_status: str | None = None
    toolhub_outcome: str | None = None
    resume_tool: str | None = None
    expires_at: str | None = None
    trace_id: str | None = None
    error_code: str | None = None
    error_retryable: bool | None = None
    message: str = ""


@dataclass
class RepairDiffSummary:
    path: str | None
    additions: int | None
    deletions: int | None
    binary: bool


@dataclass
class RepairSession:
    session_id: str
    created_at: str
    target_repository: str
    phase: RepairPhase
    finding_id: str
    finding_title: str
    target_file: str
    expected_hash: str
    proposed_hash: str
    verification_plan: tuple[VerificationPlan, ...]
    operations: list[RepairOperation]
    patch_trace_id: str | None = None
    patch_new_hash: str | None = None
    diff_summary: RepairDiffSummary | None = None
    error: str = ""
    backend: str = "mcp"
    session_type: str = "repair"
    schema_version: int = REPAIR_SESSION_SCHEMA_VERSION

    @property
    def target_path(self) -> Path:
        return Path(self.target_repository)

    @property
    def pending_operations(self) -> list[RepairOperation]:
        return [item for item in self.operations if item.status is RepairOperationStatus.PENDING]

    @property
    def patch_operation(self) -> RepairOperation | None:
        return next(
            (item for item in self.operations if item.kind is RepairOperationKind.PATCH),
            None,
        )


class RepairExecutionBackend(Protocol):
    def __enter__(self) -> RepairExecutionBackend: ...

    def __exit__(self, *exc_info: object) -> None: ...

    def request_status(self, request_id: str) -> RequestStatusResult: ...

    def run_approved_mutation(
        self,
        request_id: str,
        *,
        resume_tool: str | None = None,
        expected_path: str,
        expected_trace_id: str,
    ) -> PatchMutationResult: ...

    def run_command(
        self,
        name: str,
        command: tuple[str, ...],
        cwd: str = ".",
        timeout: int = 120,
    ) -> CommandResult: ...

    def run_approved(
        self,
        request_id: str,
        *,
        name: str,
        resume_tool: str | None = None,
    ) -> CommandResult: ...

    def git_diff(self, path: str | None = None, staged: bool = False) -> GitDiffResult: ...


def new_repair_session(
    root: Path,
    *,
    finding_id: str,
    finding_title: str,
    target_file: str,
    expected_hash: str,
    proposed_hash: str,
    verification_plan: tuple[VerificationPlan, ...],
) -> RepairSession:
    """Create an in-memory diagnosed repair before its mutation is submitted."""
    target = _canonical_existing_directory(root)
    return RepairSession(
        session_id=secrets.token_hex(16),
        created_at=datetime.now(UTC).isoformat(),
        target_repository=str(target),
        phase=RepairPhase.DIAGNOSED,
        finding_id=finding_id,
        finding_title=finding_title,
        target_file=target_file,
        expected_hash=expected_hash,
        proposed_hash=proposed_hash,
        verification_plan=verification_plan,
        operations=[],
    )


def record_patch_request(session: RepairSession, result: PatchMutationResult) -> None:
    """Record the ToolHub mutation request without retaining its patch body."""
    if session.operations or session.phase is not RepairPhase.DIAGNOSED:
        raise SessionError("Repair patch request has already been recorded.")
    if result.path != session.target_file:
        raise SessionError("ToolHub returned a different mutation target path.")
    if result.toolhub_outcome == ContractOutcome.SUCCEEDED.value and result.executed:
        status = RepairOperationStatus.COMPLETED
        phase = RepairPhase.PATCH_APPLIED
    elif result.toolhub_outcome == ContractOutcome.APPROVAL_REQUIRED.value:
        if not result.request_id:
            raise SessionError("APPROVAL_REQUIRED patch has no ToolHub request ID.")
        _require_contract_handle(result.resume_tool, result.expires_at, "filesystem.apply_patch")
        status = RepairOperationStatus.PENDING
        phase = RepairPhase.PATCH_PENDING
    else:
        status = _operation_status_from_outcome(result.toolhub_outcome)
        phase = _patch_refusal_phase(status)
    trace_id = _required_text(result.trace_id, "Patch trace_id")
    message = _safe_text(result.message)
    session.operations.append(
        RepairOperation(
            operation_id="patch-1",
            kind=RepairOperationKind.PATCH,
            status=status,
            name="AI repair patch",
            request_id=result.request_id,
            target_file=session.target_file,
            expected_hash=session.expected_hash,
            toolhub_status=_stored_toolhub_status(result.approval_status),
            toolhub_outcome=result.toolhub_outcome,
            resume_tool=result.resume_tool,
            expires_at=result.expires_at,
            trace_id=trace_id,
            error_code=result.error_code,
            error_retryable=result.error_retryable,
            message=message,
        )
    )
    session.patch_trace_id = trace_id
    session.patch_new_hash = result.new_hash
    session.phase = phase
    if phase is RepairPhase.ERROR:
        session.error = message or "ToolHub returned an unknown patch approval state."


def record_patch_conflict(session: RepairSession, error: MutationConflictError | str) -> None:
    """Persist a pre-request optimistic-concurrency conflict."""
    session.phase = RepairPhase.PATCH_CONFLICT
    session.error = _safe_text(str(error))
    session.patch_trace_id = getattr(error, "trace_id", None)
    if not session.operations:
        session.operations.append(
            RepairOperation(
                operation_id="patch-1",
                kind=RepairOperationKind.PATCH,
                status=RepairOperationStatus.CONFLICT,
                name="AI repair patch",
                target_file=session.target_file,
                expected_hash=session.expected_hash,
                toolhub_outcome=ContractOutcome.CONFLICT.value,
                trace_id=getattr(error, "trace_id", None),
                error_code=getattr(error, "error_code", None),
                message=session.error,
            )
        )


def save_repair_session(session: RepairSession, *, root: Path | None = None) -> Path:
    """Validate and atomically persist repair orchestration state."""
    payload = _session_to_data(session)
    _session_from_data(payload)
    encoded = encode_session_payload(payload)
    destination = session_file_path(session.session_id, root=root)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.parent / f".{session.session_id}.{secrets.token_hex(8)}.tmp"
    try:
        with temporary.open("xb") as stream:
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            temporary.chmod(0o600)
        except OSError:
            pass
        os.replace(temporary, destination)
    finally:
        if temporary.exists():
            temporary.unlink()
    return destination


def is_repair_session(session_id: str, *, root: Path | None = None) -> bool:
    """Return whether the trusted session document declares the repair schema."""
    path = find_session_file(session_id, root=root)
    data = _read_session_json(path)
    return isinstance(data, dict) and data.get("session_type") == "repair"


def load_repair_session(session_id: str, *, root: Path | None = None) -> RepairSession:
    path = find_session_file(session_id, root=root)
    session = _session_from_data(_read_session_json(path))
    if session.session_id != session_id:
        raise SessionError("Session file ID does not match the requested session ID.")
    expected = session_file_path(session.session_id, root=root).resolve(strict=False)
    if not _same_path(path.resolve(strict=True), expected):
        raise SessionError(
            "Session file is not stored under the trusted Repo Doctor state directory."
        )
    return session


def resume_repair_session(
    session: RepairSession,
    *,
    timeout: int = 120,
    backend_factory: Callable[[Path], RepairExecutionBackend] | None = None,
    persist: Callable[[RepairSession], object] = save_repair_session,
) -> RepairSession:
    """Advance mutation and verification approvals, persisting every transition."""
    target = _canonical_existing_directory(session.target_path)
    if not _same_path(target, Path(session.target_repository)):
        raise SessionError("Stored target repository is not a canonical absolute path.")
    if session.backend != "mcp":
        raise SessionError("Only MCP-backed repair sessions can be resumed.")
    if session.phase in {
        RepairPhase.VERIFIED_PASS,
        RepairPhase.PATCH_REJECTED,
        RepairPhase.PATCH_EXPIRED,
        RepairPhase.PATCH_CONFLICT,
        RepairPhase.VERIFICATION_FAILED,
        RepairPhase.VERIFICATION_REJECTED,
        RepairPhase.VERIFICATION_EXPIRED,
        RepairPhase.ERROR,
    }:
        return session

    factory = backend_factory or MCPToolBackend
    with factory(target) as backend:
        if session.phase is RepairPhase.PATCH_PENDING:
            patch = session.patch_operation
            if patch is None or patch.request_id is None:
                raise SessionError("Pending repair has no patch approval request.")
            status = backend.request_status(patch.request_id)
            _record_repair_status(patch, status, "filesystem.apply_patch")
            session.phase = _patch_phase_from_status(patch.status)
            if patch.status in {
                RepairOperationStatus.CONSUMED,
                RepairOperationStatus.REFUSED,
                RepairOperationStatus.UNKNOWN,
            }:
                session.error = patch.message or (
                    "Patch approval was consumed or unavailable; Repo Doctor did not replay it."
                )
            persist(session)
            if status.outcome is not ContractOutcome.APPROVAL_APPROVED:
                return session
            approval = status.approval
            if approval is None:  # Contract parser already enforces this.
                raise SessionError("APPROVAL_APPROVED status has no approval handle.")
            if patch.trace_id is None:
                raise SessionError("Pending patch approval has no lifecycle trace_id.")
            try:
                result = backend.run_approved_mutation(
                    patch.request_id,
                    resume_tool=approval.resume_tool,
                    expected_path=session.target_file,
                    expected_trace_id=patch.trace_id,
                )
            except MutationConflictError as error:
                if error.trace_id is not None and error.trace_id != patch.trace_id:
                    raise SessionError(
                        "ToolHub patch conflict returned a different lifecycle trace_id."
                    ) from error
                patch.status = RepairOperationStatus.CONFLICT
                patch.message = _safe_text(str(error))
                patch.toolhub_outcome = ContractOutcome.CONFLICT.value
                patch.error_code = error.error_code
                session.phase = RepairPhase.PATCH_CONFLICT
                session.error = patch.message
                persist(session)
                return session
            _record_approved_patch_result(session, patch, result)
            persist(session)
            if session.phase is not RepairPhase.PATCH_APPLIED:
                return session
            _update_diff(session, backend)
            persist(session)

        if session.phase in {RepairPhase.PATCH_APPLIED, RepairPhase.VERIFICATION_PENDING}:
            _resume_verification_operations(session, backend, persist)
            _submit_missing_verifications(session, backend, timeout, persist)
            session.phase = _derive_verification_phase(session)
            _update_diff(session, backend)
            persist(session)
    return session


def render_repair_session(session: RepairSession) -> str:
    """Render bounded operator-facing state for one MCP repair."""
    lines = [
        "Repo Doctor MCP Repair",
        f"Session: {session.session_id}",
        f"State: {session.phase.value.upper()}",
        f"Finding: {session.finding_id} - {session.finding_title}",
        f"File: {session.target_file}",
    ]
    for operation in session.operations:
        label = "Patch" if operation.kind is RepairOperationKind.PATCH else operation.name
        status = operation.status.value.upper()
        detail = f"{label}: {status}"
        if operation.request_id:
            detail += f" (request {operation.request_id})"
        lines.append(detail)
        if operation.kind is RepairOperationKind.VERIFICATION and operation.exit_code is not None:
            lines.append(f"  exit code: {operation.exit_code}")
        if operation.kind is RepairOperationKind.VERIFICATION and operation.trace_id:
            lines.append(f"  trace: {operation.trace_id}")
    if session.diff_summary is not None:
        summary = session.diff_summary
        lines.append(
            "Diff: "
            f"+{summary.additions if summary.additions is not None else '?'} "
            f"-{summary.deletions if summary.deletions is not None else '?'}"
            + (" (binary)" if summary.binary else "")
        )
    if session.patch_trace_id:
        lines.append(f"Patch trace: {session.patch_trace_id}")
    if session.error:
        lines.append(f"Error: {session.error}")
    return "\n".join(lines)


def _record_approved_patch_result(
    session: RepairSession,
    operation: RepairOperation,
    result: PatchMutationResult,
) -> None:
    if result.request_id != operation.request_id:
        raise SessionError("ToolHub returned a different patch approval request ID.")
    if result.path and result.path != session.target_file:
        raise SessionError("ToolHub returned a different approved mutation target path.")
    if result.trace_id != operation.trace_id or result.trace_id != session.patch_trace_id:
        raise SessionError("ToolHub approved patch returned a different lifecycle trace_id.")
    operation.toolhub_status = _stored_toolhub_status(result.approval_status)
    operation.toolhub_outcome = result.toolhub_outcome
    operation.resume_tool = result.resume_tool or operation.resume_tool
    operation.expires_at = result.expires_at or operation.expires_at
    operation.error_code = result.error_code
    operation.error_retryable = result.error_retryable
    operation.message = _safe_text(result.message)
    if result.toolhub_outcome == ContractOutcome.SUCCEEDED.value and result.executed:
        operation.status = RepairOperationStatus.COMPLETED
        session.patch_new_hash = result.new_hash
        session.phase = RepairPhase.PATCH_APPLIED
        return
    operation.status = _operation_status_from_outcome(result.toolhub_outcome)
    session.phase = _patch_refusal_phase(operation.status)
    if operation.status in {
        RepairOperationStatus.CONSUMED,
        RepairOperationStatus.REFUSED,
        RepairOperationStatus.UNKNOWN,
        RepairOperationStatus.FAILED,
    }:
        session.error = operation.message or (
            "Patch approval was already consumed or unknown; Repo Doctor did not replay it."
        )


def _resume_verification_operations(
    session: RepairSession,
    backend: RepairExecutionBackend,
    persist: Callable[[RepairSession], object],
) -> None:
    for operation in list(session.pending_operations):
        if operation.kind is not RepairOperationKind.VERIFICATION:
            continue
        if operation.request_id is None:
            raise SessionError("Pending verification has no ToolHub request ID.")
        status = backend.request_status(operation.request_id)
        _record_repair_status(operation, status, "shell.run")
        _record_unknown_verification_error(session, operation)
        session.phase = _derive_verification_phase(session)
        persist(session)
        if status.outcome is not ContractOutcome.APPROVAL_APPROVED:
            continue
        approval = status.approval
        if approval is None:  # Contract parser already enforces this.
            raise SessionError("APPROVAL_APPROVED status has no approval handle.")
        result = backend.run_approved(
            operation.request_id,
            name=operation.name,
            resume_tool=approval.resume_tool,
        )
        if result.request_id != operation.request_id:
            raise SessionError("ToolHub returned a different verification approval request ID.")
        _record_command_result(operation, result, expected_trace_id=operation.trace_id)
        _record_unknown_verification_error(session, operation)
        session.phase = _derive_verification_phase(session)
        persist(session)


def _submit_missing_verifications(
    session: RepairSession,
    backend: RepairExecutionBackend,
    timeout: int,
    persist: Callable[[RepairSession], object],
) -> None:
    submitted = {
        item.verification_index
        for item in session.operations
        if item.kind is RepairOperationKind.VERIFICATION
    }
    for index, plan in enumerate(session.verification_plan):
        if index in submitted:
            continue
        result = backend.run_command(plan.name, plan.command, ".", timeout)
        operation = RepairOperation(
            operation_id=f"verification-{index + 1}",
            kind=RepairOperationKind.VERIFICATION,
            status=RepairOperationStatus.UNKNOWN,
            name=plan.name,
            request_id=result.request_id,
            verification_index=index,
            command=result.command or plan.command,
        )
        _record_command_result(operation, result)
        session.operations.append(operation)
        _record_unknown_verification_error(session, operation)
        session.phase = _derive_verification_phase(session)
        persist(session)


def _record_command_result(
    operation: RepairOperation,
    result: CommandResult,
    *,
    expected_trace_id: str | None = None,
) -> None:
    trace_id = _required_text(result.trace_id, f"{operation.name} trace_id")
    if expected_trace_id is not None and trace_id != expected_trace_id:
        raise SessionError("ToolHub verification lifecycle trace_id changed during resume.")
    operation.command = result.command or operation.command
    operation.exit_code = result.exit_code if result.executed else None
    operation.stdout = _safe_text(result.stdout)
    operation.stderr = _safe_text(result.stderr)
    operation.timed_out = result.timed_out
    operation.toolhub_status = _stored_toolhub_status(result.approval_status)
    operation.toolhub_outcome = result.toolhub_outcome
    operation.resume_tool = result.resume_tool or operation.resume_tool
    operation.expires_at = result.expires_at or operation.expires_at
    operation.trace_id = trace_id
    operation.error_code = result.error_code
    operation.error_retryable = result.error_retryable
    operation.message = _safe_text(result.message)
    if (
        expected_trace_id is not None
        and result.toolhub_outcome == ContractOutcome.APPROVAL_APPROVED.value
    ):
        operation.status = RepairOperationStatus.UNKNOWN
        operation.message = _safe_text(
            "ToolHub returned APPROVAL_APPROVED without executing the approved request."
        )
        return
    operation.status = _operation_status_from_outcome(result.toolhub_outcome)
    if result.toolhub_outcome == ContractOutcome.SUCCEEDED.value and result.passed:
        operation.status = RepairOperationStatus.COMPLETED
    elif result.toolhub_outcome in {
        ContractOutcome.COMMAND_FAILED.value,
        ContractOutcome.TIMED_OUT.value,
        ContractOutcome.FAILED.value,
    }:
        operation.status = RepairOperationStatus.FAILED
    if operation.status is RepairOperationStatus.PENDING:
        _require_contract_handle(operation.resume_tool, operation.expires_at, "shell.run")


def _record_unknown_verification_error(
    session: RepairSession,
    operation: RepairOperation,
) -> None:
    if operation.status in {
        RepairOperationStatus.UNKNOWN,
        RepairOperationStatus.CONSUMED,
        RepairOperationStatus.REFUSED,
    }:
        session.error = operation.message or (
            f"ToolHub returned an unknown state for verification {operation.name}."
        )


def _derive_verification_phase(session: RepairSession) -> RepairPhase:
    verification = [
        item for item in session.operations if item.kind is RepairOperationKind.VERIFICATION
    ]
    if any(item.status is RepairOperationStatus.PENDING for item in verification):
        return RepairPhase.VERIFICATION_PENDING
    if len(verification) < len(session.verification_plan):
        return RepairPhase.PATCH_APPLIED
    if any(item.status is RepairOperationStatus.REJECTED for item in verification):
        return RepairPhase.VERIFICATION_REJECTED
    if any(item.status is RepairOperationStatus.EXPIRED for item in verification):
        return RepairPhase.VERIFICATION_EXPIRED
    if any(
        item.status in {RepairOperationStatus.UNKNOWN, RepairOperationStatus.CONSUMED}
        for item in verification
    ):
        return RepairPhase.ERROR
    if any(item.status is RepairOperationStatus.REFUSED for item in verification):
        return RepairPhase.ERROR
    if any(item.status is RepairOperationStatus.FAILED for item in verification):
        return RepairPhase.VERIFICATION_FAILED
    if verification and all(
        item.status is RepairOperationStatus.COMPLETED for item in verification
    ):
        return RepairPhase.VERIFIED_PASS
    return RepairPhase.ERROR


def _update_diff(session: RepairSession, backend: RepairExecutionBackend) -> None:
    try:
        result = backend.git_diff(session.target_file)
    except Exception as error:
        session.error = _safe_text(f"ToolHub git.diff failed: {error}")
        return
    session.diff_summary = RepairDiffSummary(
        path=result.path,
        additions=result.additions,
        deletions=result.deletions,
        binary=result.binary,
    )


def _record_repair_status(
    operation: RepairOperation,
    status: RequestStatusResult,
    initial_tool: str,
) -> None:
    if operation.request_id != status.request_id:
        raise SessionError("ToolHub returned a different approval request ID.")
    request_not_found = status.outcome is ContractOutcome.REFUSED and (
        status.error is not None and status.error.code == "REQUEST_NOT_FOUND"
    )
    if not request_not_found and status.trace_id != operation.trace_id:
        raise SessionError("ToolHub lifecycle trace_id changed for the approval request.")
    if status.approval is not None:
        expected = expected_resume_tool(initial_tool)
        if status.approval.resume_tool != expected or operation.resume_tool != expected:
            raise SessionError(f"ToolHub status returned an unsafe resume_tool for {initial_tool}.")
        operation.toolhub_status = status.approval.status.value
        operation.resume_tool = status.approval.resume_tool
        operation.expires_at = status.approval.expires_at
    else:
        operation.toolhub_status = None
    operation.toolhub_outcome = status.outcome.value
    operation.error_code = status.error.code if status.error else None
    operation.error_retryable = status.error.retryable if status.error else None
    operation.message = _safe_text(status.error.message if status.error else "")
    operation.status = _operation_status_from_outcome(status.outcome.value)
    if request_not_found:
        operation.status = RepairOperationStatus.UNKNOWN


def _operation_status_from_outcome(outcome: str | None) -> RepairOperationStatus:
    return {
        ContractOutcome.APPROVAL_REQUIRED.value: RepairOperationStatus.PENDING,
        ContractOutcome.APPROVAL_PENDING.value: RepairOperationStatus.PENDING,
        ContractOutcome.APPROVAL_APPROVED.value: RepairOperationStatus.PENDING,
        ContractOutcome.APPROVAL_REJECTED.value: RepairOperationStatus.REJECTED,
        ContractOutcome.APPROVAL_EXPIRED.value: RepairOperationStatus.EXPIRED,
        ContractOutcome.APPROVAL_CONSUMED.value: RepairOperationStatus.CONSUMED,
        ContractOutcome.SUCCEEDED.value: RepairOperationStatus.COMPLETED,
        ContractOutcome.COMMAND_FAILED.value: RepairOperationStatus.FAILED,
        ContractOutcome.TIMED_OUT.value: RepairOperationStatus.FAILED,
        ContractOutcome.CONFLICT.value: RepairOperationStatus.CONFLICT,
        ContractOutcome.REFUSED.value: RepairOperationStatus.REFUSED,
        ContractOutcome.FAILED.value: RepairOperationStatus.FAILED,
    }.get(outcome, RepairOperationStatus.UNKNOWN)


def _stored_toolhub_status(status: str | None) -> str | None:
    if status in {"PENDING", "APPROVED", "REJECTED", "EXPIRED", "CONSUMED"}:
        return status
    return None


def _patch_refusal_phase(status: RepairOperationStatus) -> RepairPhase:
    return {
        RepairOperationStatus.PENDING: RepairPhase.PATCH_PENDING,
        RepairOperationStatus.REJECTED: RepairPhase.PATCH_REJECTED,
        RepairOperationStatus.EXPIRED: RepairPhase.PATCH_EXPIRED,
        RepairOperationStatus.CONFLICT: RepairPhase.PATCH_CONFLICT,
    }.get(status, RepairPhase.ERROR)


def _patch_phase_from_status(status: RepairOperationStatus) -> RepairPhase:
    if status is RepairOperationStatus.PENDING:
        return RepairPhase.PATCH_PENDING
    return _patch_refusal_phase(status)


def _require_contract_handle(
    resume_tool: object,
    expires_at: object,
    initial_tool: str,
) -> None:
    expected = expected_resume_tool(initial_tool)
    if resume_tool != expected:
        raise SessionError(f"Approval handle has an unsafe resume_tool for {initial_tool}.")
    _timestamp(expires_at, "approval expires_at")


def _safe_text(value: object, limit: int = MAX_REPAIR_OUTPUT_CHARS) -> str:
    return redact_sensitive_text(str(value))[-limit:]


def _read_session_json(path: Path) -> object:
    try:
        resolved = path.expanduser().resolve(strict=True)
        if resolved.stat().st_size > MAX_SESSION_BYTES:
            raise SessionError(f"Session file is larger than {MAX_SESSION_BYTES} bytes.")
        return json.loads(resolved.read_text(encoding="utf-8"))
    except SessionError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SessionError(f"Could not read session file '{path}': {error}") from error


def _session_to_data(session: RepairSession) -> dict[str, Any]:
    return {
        "schema_version": session.schema_version,
        "session_type": session.session_type,
        "session_id": session.session_id,
        "created_at": session.created_at,
        "target_repository": session.target_repository,
        "backend": session.backend,
        "phase": session.phase.value,
        "finding_id": session.finding_id,
        "finding_title": session.finding_title,
        "target_file": session.target_file,
        "expected_hash": session.expected_hash,
        "proposed_hash": session.proposed_hash,
        "patch_trace_id": session.patch_trace_id,
        "patch_new_hash": session.patch_new_hash,
        "verification_plan": [
            {"name": item.name, "command": list(item.command)} for item in session.verification_plan
        ],
        "operations": [_operation_to_data(item) for item in session.operations],
        "diff_summary": _diff_to_data(session.diff_summary),
        "error": _safe_text(session.error),
    }


def _operation_to_data(item: RepairOperation) -> dict[str, Any]:
    return {
        "operation_id": item.operation_id,
        "kind": item.kind.value,
        "status": item.status.value,
        "name": item.name,
        "request_id": item.request_id,
        "target_file": item.target_file,
        "expected_hash": item.expected_hash,
        "verification_index": item.verification_index,
        "command": list(item.command),
        "exit_code": item.exit_code,
        "stdout": _safe_text(item.stdout),
        "stderr": _safe_text(item.stderr),
        "timed_out": item.timed_out,
        "toolhub_status": item.toolhub_status,
        "toolhub_outcome": item.toolhub_outcome,
        "resume_tool": item.resume_tool,
        "expires_at": item.expires_at,
        "trace_id": item.trace_id,
        "error_code": item.error_code,
        "error_retryable": item.error_retryable,
        "message": _safe_text(item.message),
    }


def _diff_to_data(summary: RepairDiffSummary | None) -> dict[str, Any] | None:
    if summary is None:
        return None
    return {
        "path": summary.path,
        "additions": summary.additions,
        "deletions": summary.deletions,
        "binary": summary.binary,
    }


def _session_from_data(value: object) -> RepairSession:
    value = _migrate_v1_repair_session(value)
    keys = {
        "schema_version",
        "session_type",
        "session_id",
        "created_at",
        "target_repository",
        "backend",
        "phase",
        "finding_id",
        "finding_title",
        "target_file",
        "expected_hash",
        "proposed_hash",
        "patch_trace_id",
        "patch_new_hash",
        "verification_plan",
        "operations",
        "diff_summary",
        "error",
    }
    data = _object(value, "repair session", keys)
    version = _integer(data["schema_version"], "schema_version")
    if version != REPAIR_SESSION_SCHEMA_VERSION:
        raise SessionError(
            f"Unsupported repair session schema version {version}; "
            f"expected {REPAIR_SESSION_SCHEMA_VERSION}."
        )
    if _text(data["session_type"], "session_type") != "repair":
        raise SessionError("Repair session_type must be 'repair'.")
    session_id = _session_id(data["session_id"])
    created_at = _text(data["created_at"], "created_at")
    try:
        created = datetime.fromisoformat(created_at)
    except ValueError as error:
        raise SessionError("created_at must be an ISO-8601 timestamp.") from error
    if created.tzinfo is None:
        raise SessionError("created_at must include a timezone.")
    target_repository = _text(data["target_repository"], "target_repository")
    target = Path(target_repository)
    if not target.is_absolute() or not _is_canonical_path(target):
        raise SessionError("target_repository must be a canonical absolute path.")
    if _text(data["backend"], "backend") != "mcp":
        raise SessionError("Repair session backend must be 'mcp'.")
    try:
        phase = RepairPhase(_text(data["phase"], "phase"))
    except ValueError as error:
        raise SessionError("Repair phase is invalid.") from error
    verification_value = data["verification_plan"]
    operations_value = data["operations"]
    if not isinstance(verification_value, list) or len(verification_value) > MAX_REPAIR_COMMANDS:
        raise SessionError("verification_plan must be a bounded list.")
    if not isinstance(operations_value, list) or len(operations_value) > MAX_REPAIR_OPERATIONS:
        raise SessionError("operations must be a bounded list.")
    verification_plan = tuple(
        _verification_from_data(item, index) for index, item in enumerate(verification_value)
    )
    operations = [_operation_from_data(item, index) for index, item in enumerate(operations_value)]
    session = RepairSession(
        session_id=session_id,
        created_at=created_at,
        target_repository=target_repository,
        phase=phase,
        finding_id=_text(data["finding_id"], "finding_id"),
        finding_title=_text(data["finding_title"], "finding_title"),
        target_file=_relative_path(data["target_file"], "target_file"),
        expected_hash=_sha256(data["expected_hash"], "expected_hash"),
        proposed_hash=_sha256(data["proposed_hash"], "proposed_hash"),
        verification_plan=verification_plan,
        operations=operations,
        patch_trace_id=_optional_text(data["patch_trace_id"], "patch_trace_id"),
        patch_new_hash=_optional_sha256(data["patch_new_hash"], "patch_new_hash"),
        diff_summary=_diff_from_data(data["diff_summary"]),
        error=_text(data["error"], "error", max_length=MAX_REPAIR_OUTPUT_CHARS),
        backend="mcp",
        session_type="repair",
        schema_version=version,
    )
    _validate_repair_session(session)
    return session


def _migrate_v1_repair_session(value: object) -> object:
    """Load schema v1 while making every unresolved approval non-resumable."""
    if not isinstance(value, dict) or value.get("schema_version") != 1:
        return value
    migrated = deepcopy(value)
    operations = migrated.get("operations")
    if not isinstance(operations, list):
        return migrated
    unresolved = False
    for operation in operations:
        if not isinstance(operation, dict):
            continue
        if operation.get("status") == RepairOperationStatus.PENDING.value:
            operation["status"] = RepairOperationStatus.UNKNOWN.value
            unresolved = True
        operation.update(
            {
                "toolhub_outcome": None,
                "resume_tool": None,
                "expires_at": None,
                "error_code": None,
                "error_retryable": None,
            }
        )
    if unresolved:
        migrated["phase"] = RepairPhase.ERROR.value
        detail = "Schema-v1 approval requests are non-resumable under Contract V1."
        migrated["error"] = f"{detail} {migrated.get('error', '')}".strip()
    migrated["schema_version"] = REPAIR_SESSION_SCHEMA_VERSION
    return migrated


def _verification_from_data(value: object, index: int) -> VerificationPlan:
    label = f"verification_plan[{index}]"
    data = _object(value, label, {"name", "command"})
    command = tuple(_text_list(data["command"], f"{label}.command"))
    if not command:
        raise SessionError(f"{label}.command must not be empty.")
    return VerificationPlan(_text(data["name"], f"{label}.name"), command)


def _operation_from_data(value: object, index: int) -> RepairOperation:
    label = f"operations[{index}]"
    data = _object(
        value,
        label,
        {
            "operation_id",
            "kind",
            "status",
            "name",
            "request_id",
            "target_file",
            "expected_hash",
            "verification_index",
            "command",
            "exit_code",
            "stdout",
            "stderr",
            "timed_out",
            "toolhub_status",
            "toolhub_outcome",
            "resume_tool",
            "expires_at",
            "trace_id",
            "error_code",
            "error_retryable",
            "message",
        },
    )
    try:
        kind = RepairOperationKind(_text(data["kind"], f"{label}.kind"))
        status = RepairOperationStatus(_text(data["status"], f"{label}.status"))
    except ValueError as error:
        raise SessionError(f"{label} kind or status is invalid.") from error
    verification_index = data["verification_index"]
    if verification_index is not None:
        verification_index = _nonnegative_integer(verification_index, f"{label}.verification_index")
    exit_code = data["exit_code"]
    if exit_code is not None:
        exit_code = _integer(exit_code, f"{label}.exit_code")
    error_retryable = data["error_retryable"]
    if error_retryable is not None:
        error_retryable = _boolean(error_retryable, f"{label}.error_retryable")
    return RepairOperation(
        operation_id=_text(data["operation_id"], f"{label}.operation_id"),
        kind=kind,
        status=status,
        name=_text(data["name"], f"{label}.name"),
        request_id=_optional_request_id(data["request_id"], f"{label}.request_id"),
        target_file=(
            _relative_path(data["target_file"], f"{label}.target_file")
            if data["target_file"] is not None
            else None
        ),
        expected_hash=_optional_sha256(data["expected_hash"], f"{label}.expected_hash"),
        verification_index=verification_index,
        command=tuple(_text_list(data["command"], f"{label}.command")),
        exit_code=exit_code,
        stdout=_text(data["stdout"], f"{label}.stdout", max_length=MAX_REPAIR_OUTPUT_CHARS),
        stderr=_text(data["stderr"], f"{label}.stderr", max_length=MAX_REPAIR_OUTPUT_CHARS),
        timed_out=_boolean(data["timed_out"], f"{label}.timed_out"),
        toolhub_status=_optional_status(data["toolhub_status"], f"{label}.toolhub_status"),
        toolhub_outcome=_optional_outcome(data["toolhub_outcome"], f"{label}.toolhub_outcome"),
        resume_tool=_optional_text(data["resume_tool"], f"{label}.resume_tool"),
        expires_at=_optional_timestamp(data["expires_at"], f"{label}.expires_at"),
        trace_id=_optional_text(data["trace_id"], f"{label}.trace_id"),
        error_code=_optional_text(data["error_code"], f"{label}.error_code"),
        error_retryable=error_retryable,
        message=_text(data["message"], f"{label}.message", max_length=MAX_REPAIR_OUTPUT_CHARS),
    )


def _diff_from_data(value: object) -> RepairDiffSummary | None:
    if value is None:
        return None
    data = _object(value, "diff_summary", {"path", "additions", "deletions", "binary"})
    path = data["path"]
    if path is not None:
        path = _relative_path(path, "diff_summary.path")
    additions = data["additions"]
    deletions = data["deletions"]
    if additions is not None:
        additions = _nonnegative_integer(additions, "diff_summary.additions")
    if deletions is not None:
        deletions = _nonnegative_integer(deletions, "diff_summary.deletions")
    return RepairDiffSummary(
        path=path,
        additions=additions,
        deletions=deletions,
        binary=_boolean(data["binary"], "diff_summary.binary"),
    )


def _validate_repair_session(session: RepairSession) -> None:
    if not session.verification_plan:
        raise SessionError("MCP repair requires at least one verification command.")
    ids: set[str] = set()
    indexes: set[int] = set()
    patch_count = 0
    for operation in session.operations:
        if operation.operation_id in ids:
            raise SessionError("Repair operation IDs must be unique.")
        ids.add(operation.operation_id)
        if operation.kind is RepairOperationKind.PATCH:
            patch_count += 1
            if (
                operation.target_file != session.target_file
                or operation.expected_hash != session.expected_hash
                or operation.verification_index is not None
                or operation.command
            ):
                raise SessionError("Patch operation metadata does not match the repair target.")
        else:
            if operation.verification_index is None:
                raise SessionError("Verification operation is missing its plan index.")
            if operation.verification_index >= len(session.verification_plan):
                raise SessionError("Verification operation index is outside the plan.")
            if operation.verification_index in indexes:
                raise SessionError("Verification operation indexes must be unique.")
            indexes.add(operation.verification_index)
            plan = session.verification_plan[operation.verification_index]
            if operation.name != plan.name or operation.command != plan.command:
                raise SessionError("Verification operation does not match its stored plan.")
        if operation.status is RepairOperationStatus.PENDING and operation.request_id is None:
            raise SessionError("Pending repair operation must have a ToolHub request ID.")
        if operation.resume_tool is not None:
            initial_tool = (
                "filesystem.apply_patch"
                if operation.kind is RepairOperationKind.PATCH
                else "shell.run"
            )
            if operation.resume_tool != expected_resume_tool(initial_tool):
                raise SessionError("Repair operation contains an unsafe resume_tool.")
        if operation.status is RepairOperationStatus.PENDING:
            if (
                operation.trace_id is None
                or operation.expires_at is None
                or operation.resume_tool is None
                or operation.toolhub_outcome
                not in {
                    ContractOutcome.APPROVAL_REQUIRED.value,
                    ContractOutcome.APPROVAL_PENDING.value,
                    ContractOutcome.APPROVAL_APPROVED.value,
                }
            ):
                raise SessionError("Pending repair operation lacks Contract V1 approval metadata.")
        if (
            operation.status
            in {
                RepairOperationStatus.COMPLETED,
                RepairOperationStatus.FAILED,
            }
            and operation.kind is RepairOperationKind.VERIFICATION
            and operation.exit_code is None
        ):
            raise SessionError("Executed verification must retain its exit code.")
    if patch_count > 1:
        raise SessionError("Repair session may contain only one patch operation.")
    patch = session.patch_operation
    if patch is not None and patch.trace_id != session.patch_trace_id:
        raise SessionError("Patch operation trace_id does not match the repair lifecycle trace.")
    if session.phase is RepairPhase.DIAGNOSED and session.operations:
        raise SessionError("Diagnosed repair cannot already contain operations.")
    if session.phase is not RepairPhase.DIAGNOSED and patch is None:
        raise SessionError("Repair phase requires a patch operation.")
    if session.phase is RepairPhase.PATCH_PENDING and (
        patch is None or patch.status is not RepairOperationStatus.PENDING
    ):
        raise SessionError("PATCH_PENDING requires one pending patch operation.")
    if session.phase is RepairPhase.PATCH_APPLIED and (
        patch is None or patch.status is not RepairOperationStatus.COMPLETED
    ):
        raise SessionError("PATCH_APPLIED requires a completed patch operation.")
    patch_terminal = {
        RepairPhase.PATCH_REJECTED: RepairOperationStatus.REJECTED,
        RepairPhase.PATCH_EXPIRED: RepairOperationStatus.EXPIRED,
        RepairPhase.PATCH_CONFLICT: RepairOperationStatus.CONFLICT,
    }
    expected_patch_status = patch_terminal.get(session.phase)
    if expected_patch_status is not None and (
        patch is None or patch.status is not expected_patch_status
    ):
        raise SessionError(f"{session.phase.value.upper()} does not match the patch result.")
    if session.phase is RepairPhase.VERIFICATION_PENDING and not any(
        item.kind is RepairOperationKind.VERIFICATION
        and item.status is RepairOperationStatus.PENDING
        for item in session.operations
    ):
        raise SessionError("VERIFICATION_PENDING requires a pending verification.")
    if (
        session.phase is RepairPhase.VERIFIED_PASS
        and _derive_verification_phase(session) is not RepairPhase.VERIFIED_PASS
    ):
        raise SessionError("VERIFIED_PASS does not match verification results.")
    verification_terminal = {
        RepairPhase.VERIFICATION_FAILED,
        RepairPhase.VERIFICATION_REJECTED,
        RepairPhase.VERIFICATION_EXPIRED,
    }
    if (
        session.phase in verification_terminal
        and _derive_verification_phase(session) is not session.phase
    ):
        raise SessionError(f"{session.phase.value.upper()} does not match verification results.")


def _canonical_existing_directory(path: Path) -> Path:
    try:
        resolved = path.expanduser().resolve(strict=True)
    except OSError as error:
        raise SessionError(f"Target repository no longer exists: {path}") from error
    if not resolved.is_dir():
        raise SessionError(f"Target repository is not a directory: {resolved}")
    return resolved


def _same_path(left: Path, right: Path) -> bool:
    return os.path.normcase(str(left.resolve(strict=False))) == os.path.normcase(
        str(right.resolve(strict=False))
    )


def _is_canonical_path(path: Path) -> bool:
    return os.path.normcase(str(path)) == os.path.normcase(str(path.resolve(strict=False)))


def _object(value: object, label: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise SessionError(f"{label} has missing or unexpected fields.")
    return value


def _text(value: object, label: str, *, max_length: int = 20_000) -> str:
    if not isinstance(value, str) or len(value) > max_length or "\x00" in value:
        raise SessionError(f"{label} must be bounded text without null bytes.")
    return value


def _optional_text(value: object, label: str) -> str | None:
    return None if value is None else _text(value, label)


def _required_text(value: object, label: str) -> str:
    text = _text(value, label)
    if not text:
        raise SessionError(f"{label} must be non-empty text.")
    return text


def _timestamp(value: object, label: str) -> str:
    text = _required_text(value, label)
    try:
        parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError as error:
        raise SessionError(f"{label} must be an ISO-8601 timestamp.") from error
    if parsed.tzinfo is None:
        raise SessionError(f"{label} must include a timezone.")
    return text


def _optional_timestamp(value: object, label: str) -> str | None:
    return None if value is None else _timestamp(value, label)


def _optional_outcome(value: object, label: str) -> str | None:
    if value is None:
        return None
    try:
        return ContractOutcome(_text(value, label)).value
    except ValueError as error:
        raise SessionError(f"{label} is invalid.") from error


def _text_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or len(value) > 256:
        raise SessionError(f"{label} must be a bounded list of strings.")
    return [_text(item, f"{label} item") for item in value]


def _integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise SessionError(f"{label} must be an integer.")
    return value


def _nonnegative_integer(value: object, label: str) -> int:
    number = _integer(value, label)
    if number < 0:
        raise SessionError(f"{label} must not be negative.")
    return number


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise SessionError(f"{label} must be a boolean.")
    return value


def _session_id(value: object) -> str:
    text = _text(value, "session_id")
    if len(text) != 32 or any(character not in "0123456789abcdef" for character in text):
        raise SessionError("Session ID must be exactly 32 lowercase hexadecimal characters.")
    return text


def _request_id(value: object, label: str) -> str:
    text = _text(value, label, max_length=512)
    if not text or any(ord(character) < 32 for character in text):
        raise SessionError(f"{label} must be a non-empty ToolHub request ID.")
    return text


def _optional_request_id(value: object, label: str) -> str | None:
    return None if value is None else _request_id(value, label)


def _sha256(value: object, label: str) -> str:
    text = _text(value, label, max_length=64)
    if len(text) != 64 or any(character not in "0123456789abcdef" for character in text):
        raise SessionError(f"{label} must be a lowercase SHA-256 digest.")
    return text


def _optional_sha256(value: object, label: str) -> str | None:
    return None if value is None else _sha256(value, label)


def _optional_status(value: object, label: str) -> str | None:
    if value is None:
        return None
    status = _text(value, label)
    if status not in {"PENDING", "APPROVED", "REJECTED", "EXPIRED", "CONSUMED"}:
        raise SessionError(f"{label} is invalid.")
    return status


def _relative_path(value: object, label: str) -> str:
    text = _text(value, label)
    normalized = text.replace("\\", "/")
    path = Path(normalized)
    if (
        not normalized
        or path.is_absolute()
        or any(part in {"", ".."} for part in normalized.split("/"))
    ):
        raise SessionError(f"{label} must be a safe repository-relative path.")
    return normalized
