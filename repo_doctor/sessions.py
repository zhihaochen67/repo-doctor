"""Persistent orchestration state for resumable MCP verification approvals."""

from __future__ import annotations

import json
import math
import os
import re
import secrets
from collections.abc import Callable
from copy import deepcopy
from dataclasses import dataclass, replace
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any, Protocol

from .ai.models import SemanticFinding, Severity
from .analyzer import analyze, apply_ai_score
from .backends import MCPToolBackend
from .models import CommandResult, ScanResult
from .security import redact_sensitive_text
from .toolhub_contract import (
    ContractOutcome,
    RequestStatusResult,
    expected_resume_tool,
)

STATE_ROOT_ENV = "REPO_DOCTOR_STATE_ROOT"
SESSION_SCHEMA_VERSION = 2
SESSIONS_DIRECTORY_NAME = "sessions"
MAX_SESSION_BYTES = 1_000_000
MAX_PERSISTED_OUTPUT_CHARS = 4_000
SESSION_ID_PATTERN = re.compile(r"[0-9a-f]{32}")


class SessionError(ValueError):
    """A scan session is missing, malformed, or unsafe to resume."""


class OperationStatus(StrEnum):
    """Local orchestration outcomes; deliberately has no APPROVED state."""

    PENDING = "pending"
    COMPLETED = "completed"
    REJECTED = "rejected"
    EXPIRED = "expired"
    CONSUMED = "consumed"
    REFUSED = "refused"
    FAILED = "failed"
    UNKNOWN = "unknown"


class SessionStatus(StrEnum):
    """Aggregate local progress for a scan session."""

    PENDING = "pending"
    PARTIAL = "partial"
    COMPLETED = "completed"
    UNABLE_TO_CONTINUE = "unable_to_continue"


@dataclass
class ApprovalOperation:
    """One ToolHub request and its report presentation metadata."""

    operation_id: str
    verification_kind: str
    request_id: str
    status: OperationStatus
    command_index: int
    name: str
    command: tuple[str, ...]
    toolhub_outcome: str | None
    resume_tool: str | None
    expires_at: str | None
    trace_id: str | None


@dataclass
class ScanSession:
    """Versioned state needed to resume a root-bound MCP scan."""

    session_id: str
    created_at: str
    target_repository: str
    backend: str
    status: SessionStatus
    result: ScanResult
    operations: list[ApprovalOperation]
    schema_version: int = SESSION_SCHEMA_VERSION

    @property
    def target_path(self) -> Path:
        return Path(self.target_repository)

    @property
    def pending_operations(self) -> list[ApprovalOperation]:
        return [item for item in self.operations if item.status is OperationStatus.PENDING]


class ApprovedExecutionBackend(Protocol):
    """Backend behavior used by the resume orchestrator."""

    def __enter__(self) -> ApprovedExecutionBackend: ...

    def __exit__(self, *exc_info: object) -> None: ...

    def request_status(self, request_id: str) -> RequestStatusResult: ...

    def run_approved(
        self,
        request_id: str,
        *,
        name: str,
        resume_tool: str | None = None,
    ) -> CommandResult: ...


def create_scan_session(result: ScanResult) -> ScanSession:
    """Create, but do not yet persist, a session for pending MCP commands."""
    root = _canonical_existing_directory(result.path)
    operations: list[ApprovalOperation] = []
    for index, command in enumerate(result.commands):
        if not command.approval_required:
            continue
        if command.toolhub_outcome != ContractOutcome.APPROVAL_REQUIRED.value:
            raise SessionError("Pending command is not a Contract V1 APPROVAL_REQUIRED result.")
        request_id = _request_id(command.request_id, f"command {index} request_id")
        resume_tool = _expected_resume_tool(command.resume_tool, "shell.run")
        trace_id = _required_text(command.trace_id, f"command {index} trace_id")
        expires_at = _timestamp(command.expires_at, f"command {index} expires_at")
        operations.append(
            ApprovalOperation(
                operation_id=f"verification-{index + 1}",
                verification_kind=_verification_kind(command.name),
                request_id=request_id,
                status=OperationStatus.PENDING,
                command_index=index,
                name=command.name,
                command=command.command,
                toolhub_outcome=command.toolhub_outcome,
                resume_tool=resume_tool,
                expires_at=expires_at,
                trace_id=trace_id,
            )
        )
    if not operations:
        raise SessionError("An MCP scan session requires at least one pending approval request.")
    result.path = root
    return ScanSession(
        session_id=secrets.token_hex(16),
        created_at=datetime.now(UTC).isoformat(),
        target_repository=str(root),
        backend="mcp",
        status=SessionStatus.PENDING,
        result=result,
        operations=operations,
    )


def default_state_root() -> Path:
    """Return the default cross-platform user-level Repo Doctor state directory."""
    if os.name == "nt":
        base = os.environ.get("LOCALAPPDATA")
        if base:
            return Path(base) / "repo-doctor"
        return Path.home() / ".repo-doctor"
    base = os.environ.get("XDG_STATE_HOME")
    if base:
        return Path(base) / "repo-doctor"
    return Path.home() / ".local" / "state" / "repo-doctor"


def state_root() -> Path:
    """Return the trusted Repo Doctor state root, honoring STATE_ROOT_ENV."""
    configured = os.environ.get(STATE_ROOT_ENV)
    if configured is None:
        return default_state_root()
    root = Path(configured).expanduser()
    if not root.is_absolute():
        raise SessionError(f"{STATE_ROOT_ENV} must be an absolute path, got {configured!r}.")
    return root


def sessions_directory(root: Path | None = None) -> Path:
    """Return the session directory under the trusted Repo Doctor state root."""
    base = root or state_root()
    if not base.is_absolute():
        raise SessionError("The Repo Doctor state root must be an absolute path.")
    return base / SESSIONS_DIRECTORY_NAME


def session_file_path(session_id: str, *, root: Path | None = None) -> Path:
    """Return the fixed state-root path for a validated session ID."""
    _session_id(session_id)
    return sessions_directory(root) / f"{session_id}.json"


def save_session(session: ScanSession, *, root: Path | None = None) -> Path:
    """Atomically persist a validated session under the Repo Doctor state root."""
    session.status = _derive_session_status(session.operations)
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


def encode_session_payload(payload: object) -> bytes:
    """Serialize exactly once and reject files the bounded loader cannot read."""
    encoded = (json.dumps(payload, ensure_ascii=False, indent=2, sort_keys=True) + "\n").encode(
        "utf-8"
    )
    if len(encoded) > MAX_SESSION_BYTES:
        raise SessionError(f"Session data exceeds the {MAX_SESSION_BYTES}-byte safety limit.")
    return encoded


def find_session_file(session_id: str, *, root: Path | None = None) -> Path:
    """Find one session under the trusted Repo Doctor state root."""
    _session_id(session_id)
    candidate = session_file_path(session_id, root=root)
    if candidate.is_file():
        return candidate
    raise SessionError(
        f"Session '{session_id}' was not found under the Repo Doctor state directory "
        f"{sessions_directory(root)}."
    )


def load_session(session_id: str, *, root: Path | None = None) -> ScanSession:
    """Locate and validate one session under the trusted Repo Doctor state root."""
    return load_session_file(
        find_session_file(session_id, root=root),
        expected_id=session_id,
        root=root,
    )


def load_session_file(
    path: Path,
    *,
    expected_id: str | None = None,
    root: Path | None = None,
) -> ScanSession:
    """Load a bounded JSON session and validate its schema and fixed location."""
    try:
        resolved_path = path.expanduser().resolve(strict=True)
        if resolved_path.stat().st_size > MAX_SESSION_BYTES:
            raise SessionError(f"Session file is larger than {MAX_SESSION_BYTES} bytes.")
        raw = resolved_path.read_text(encoding="utf-8")
        data = json.loads(raw)
    except SessionError:
        raise
    except (OSError, UnicodeError, json.JSONDecodeError) as error:
        raise SessionError(f"Could not read session file '{path}': {error}") from error
    session = _session_from_data(data)
    if expected_id is not None and session.session_id != _session_id(expected_id):
        raise SessionError("Session file ID does not match the requested session ID.")
    expected_path = session_file_path(session.session_id, root=root).resolve(strict=False)
    if not _same_path(resolved_path, expected_path):
        raise SessionError(
            "Session file is not stored under the trusted Repo Doctor state directory."
        )
    return session


def resume_scan_session(
    session: ScanSession,
    *,
    backend_factory: Callable[[Path], ApprovedExecutionBackend] | None = None,
    persist: Callable[[ScanSession], object] = save_session,
) -> ScanSession:
    """Poll every unresolved request and execute only freshly APPROVED operations."""
    target = _canonical_existing_directory(session.target_path)
    if not _same_path(target, Path(session.target_repository)):
        raise SessionError("Stored target repository is not a canonical absolute path.")
    if session.backend != "mcp":
        raise SessionError("Only MCP-backed scan sessions can be resumed.")
    factory = backend_factory or MCPToolBackend
    pending = list(session.pending_operations)
    if not pending:
        _reanalyze(session.result)
        return session
    with factory(target) as backend:
        for operation in pending:
            status = backend.request_status(operation.request_id)
            _validate_status_correlation(operation, status)
            _record_status(session, operation, status)
            persist(session)
            if status.outcome is not ContractOutcome.APPROVAL_APPROVED:
                continue
            approval = status.approval
            if approval is None:  # Contract parser already enforces this.
                raise SessionError("APPROVAL_APPROVED status has no approval handle.")
            expected = expected_resume_tool("shell.run")
            if approval.resume_tool != expected or operation.resume_tool != expected:
                raise SessionError("ToolHub returned an unsafe shell resume_tool.")
            result = backend.run_approved(
                operation.request_id,
                name=operation.name,
                resume_tool=approval.resume_tool,
            )
            _validate_final_command(operation, result)
            if not result.command:
                result = replace(result, command=operation.command)
            else:
                operation.command = result.command
            operation.status = _final_command_operation_status(result)
            operation.toolhub_outcome = result.toolhub_outcome
            operation.expires_at = result.expires_at or operation.expires_at
            operation.resume_tool = result.resume_tool or operation.resume_tool
            session.result.commands[operation.command_index] = result
            _reanalyze(session.result)
            session.status = _derive_session_status(session.operations)
            persist(session)
    return session


def _validate_status_correlation(
    operation: ApprovalOperation,
    status: RequestStatusResult,
) -> None:
    if status.request_id != operation.request_id:
        raise SessionError("ToolHub returned a different approval request ID.")
    if status.outcome is ContractOutcome.REFUSED and (
        status.error is not None and status.error.code == "REQUEST_NOT_FOUND"
    ):
        return
    if status.trace_id != operation.trace_id:
        raise SessionError("ToolHub lifecycle trace_id changed for the approval request.")
    if status.approval is not None:
        expected = expected_resume_tool("shell.run")
        if status.approval.resume_tool != expected:
            raise SessionError("ToolHub status returned an unsafe shell resume_tool.")


def _record_status(
    session: ScanSession,
    operation: ApprovalOperation,
    status: RequestStatusResult,
) -> None:
    mapping = {
        ContractOutcome.APPROVAL_PENDING: OperationStatus.PENDING,
        ContractOutcome.APPROVAL_APPROVED: OperationStatus.PENDING,
        ContractOutcome.APPROVAL_REJECTED: OperationStatus.REJECTED,
        ContractOutcome.APPROVAL_EXPIRED: OperationStatus.EXPIRED,
        ContractOutcome.APPROVAL_CONSUMED: OperationStatus.CONSUMED,
        ContractOutcome.REFUSED: OperationStatus.REFUSED,
    }
    operation.status = mapping[status.outcome]
    if status.outcome is ContractOutcome.REFUSED and (
        status.error is not None and status.error.code == "REQUEST_NOT_FOUND"
    ):
        operation.status = OperationStatus.UNKNOWN
    operation.toolhub_outcome = status.outcome.value
    if status.approval is not None:
        operation.resume_tool = status.approval.resume_tool
        operation.expires_at = status.approval.expires_at
    command = session.result.commands[operation.command_index]
    approval_status = status.approval.status.value if status.approval else None
    message = status.error.message if status.error else command.message
    session.result.commands[operation.command_index] = replace(
        command,
        approval_required=status.outcome is ContractOutcome.APPROVAL_PENDING,
        approval_status=approval_status,
        message=message,
        toolhub_outcome=status.outcome.value,
        resume_tool=status.approval.resume_tool if status.approval else operation.resume_tool,
        expires_at=status.approval.expires_at if status.approval else operation.expires_at,
        error_code=status.error.code if status.error else None,
        error_retryable=status.error.retryable if status.error else None,
    )
    _reanalyze(session.result)
    session.status = _derive_session_status(session.operations)


def _validate_final_command(operation: ApprovalOperation, result: CommandResult) -> None:
    if result.request_id != operation.request_id:
        raise SessionError("ToolHub returned a different approval request ID.")
    if result.trace_id != operation.trace_id:
        raise SessionError("ToolHub approved execution returned a different lifecycle trace_id.")
    allowed = {
        ContractOutcome.SUCCEEDED.value,
        ContractOutcome.COMMAND_FAILED.value,
        ContractOutcome.TIMED_OUT.value,
        ContractOutcome.APPROVAL_PENDING.value,
        ContractOutcome.APPROVAL_REJECTED.value,
        ContractOutcome.APPROVAL_EXPIRED.value,
        ContractOutcome.APPROVAL_CONSUMED.value,
        ContractOutcome.REFUSED.value,
        ContractOutcome.FAILED.value,
    }
    if result.toolhub_outcome not in allowed:
        raise SessionError("ToolHub returned an invalid shell resume outcome.")


def _final_command_operation_status(result: CommandResult) -> OperationStatus:
    if (
        result.toolhub_outcome
        in {
            ContractOutcome.SUCCEEDED.value,
            ContractOutcome.COMMAND_FAILED.value,
            ContractOutcome.TIMED_OUT.value,
        }
        and result.executed
    ):
        return OperationStatus.COMPLETED
    return {
        ContractOutcome.APPROVAL_PENDING.value: OperationStatus.PENDING,
        ContractOutcome.APPROVAL_REJECTED.value: OperationStatus.REJECTED,
        ContractOutcome.APPROVAL_EXPIRED.value: OperationStatus.EXPIRED,
        ContractOutcome.APPROVAL_CONSUMED.value: OperationStatus.CONSUMED,
        ContractOutcome.REFUSED.value: OperationStatus.REFUSED,
        ContractOutcome.FAILED.value: OperationStatus.FAILED,
    }.get(result.toolhub_outcome, OperationStatus.UNKNOWN)


def _reanalyze(result: ScanResult) -> None:
    analyze(result)
    if result.ai_requested and result.ai_findings:
        apply_ai_score(result)


def _derive_session_status(operations: list[ApprovalOperation]) -> SessionStatus:
    pending = [item for item in operations if item.status is OperationStatus.PENDING]
    if pending:
        return SessionStatus.PARTIAL if len(pending) != len(operations) else SessionStatus.PENDING
    if all(item.status is OperationStatus.COMPLETED for item in operations):
        return SessionStatus.COMPLETED
    return SessionStatus.UNABLE_TO_CONTINUE


def _verification_kind(name: str) -> str:
    lowered = name.lower()
    if "test" in lowered:
        return "tests"
    if "lint" in lowered:
        return "lint"
    return "other"


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


def _session_id(value: str) -> str:
    if not isinstance(value, str) or SESSION_ID_PATTERN.fullmatch(value) is None:
        raise SessionError("Session ID must be exactly 32 lowercase hexadecimal characters.")
    return value


def _request_id(value: object, label: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 512
        or any(ord(character) < 32 for character in value)
    ):
        raise SessionError(f"{label} must be a non-empty ToolHub request ID.")
    return value


def _safe_text(value: str, limit: int = MAX_PERSISTED_OUTPUT_CHARS) -> str:
    return redact_sensitive_text(value[-limit:])


def _session_to_data(session: ScanSession) -> dict[str, Any]:
    return {
        "schema_version": session.schema_version,
        "session_id": session.session_id,
        "created_at": session.created_at,
        "target_repository": session.target_repository,
        "backend": session.backend,
        "status": session.status.value,
        "scan": _scan_to_data(session.result),
        "operations": [
            {
                "operation_id": item.operation_id,
                "verification_kind": item.verification_kind,
                "request_id": item.request_id,
                "status": item.status.value,
                "command_index": item.command_index,
                "name": item.name,
                "command": list(item.command),
                "toolhub_outcome": item.toolhub_outcome,
                "resume_tool": item.resume_tool,
                "expires_at": item.expires_at,
                "trace_id": item.trace_id,
            }
            for item in session.operations
        ],
    }


def _scan_to_data(result: ScanResult) -> dict[str, Any]:
    return {
        "technologies": list(result.technologies),
        "files": result.files,
        "lines": result.lines,
        "inspected_files": list(result.inspected_files),
        "commands": [_command_to_data(item) for item in result.commands],
        "potential_bugs": list(result.potential_bugs),
        "maintainability_issues": list(result.maintainability_issues),
        "deterministic_score": result.deterministic_score,
        "score": result.score,
        "ai_requested": result.ai_requested,
        "ai_findings": [_finding_to_data(item) for item in result.ai_findings],
        "ai_error": _safe_text(result.ai_error) if result.ai_error else None,
        "ai_context_files": list(result.ai_context_files),
    }


def _command_to_data(result: CommandResult) -> dict[str, Any]:
    return {
        "name": result.name,
        "command": list(result.command),
        "exit_code": result.exit_code,
        "stdout": _safe_text(result.stdout),
        "stderr": _safe_text(result.stderr),
        "duration": result.duration,
        "timed_out": result.timed_out,
        "executed": result.executed,
        "approval_required": result.approval_required,
        "request_id": result.request_id,
        "toolhub_approval_status": result.approval_status,
        "message": _safe_text(result.message),
        "toolhub_outcome": result.toolhub_outcome,
        "resume_tool": result.resume_tool,
        "expires_at": result.expires_at,
        "trace_id": result.trace_id,
        "error_code": result.error_code,
        "error_retryable": result.error_retryable,
    }


def _finding_to_data(item: SemanticFinding) -> dict[str, Any]:
    return {
        "id": item.id,
        "title": item.title,
        "category": item.category,
        "severity": item.severity.value,
        "confidence": item.confidence,
        "file": item.file,
        "line_start": item.line_start,
        "line_end": item.line_end,
        "explanation": item.explanation,
        "evidence": item.evidence,
        "suggested_fix": item.suggested_fix,
    }


def _session_from_data(value: object) -> ScanSession:
    value = _migrate_v1_session(value)
    data = _object(
        value,
        "session",
        {
            "schema_version",
            "session_id",
            "created_at",
            "target_repository",
            "backend",
            "status",
            "scan",
            "operations",
        },
    )
    version = _integer(data["schema_version"], "schema_version")
    if version != SESSION_SCHEMA_VERSION:
        raise SessionError(
            f"Unsupported session schema version {version}; expected {SESSION_SCHEMA_VERSION}."
        )
    session_id = _session_id(_text(data["session_id"], "session_id"))
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
    backend = _text(data["backend"], "backend")
    if backend != "mcp":
        raise SessionError("Session backend must be 'mcp'.")
    try:
        status = SessionStatus(_text(data["status"], "status"))
    except ValueError as error:
        raise SessionError("Session status is invalid.") from error
    result = _scan_from_data(data["scan"], target)
    operations_value = data["operations"]
    if not isinstance(operations_value, list) or not operations_value:
        raise SessionError("operations must be a non-empty list.")
    operations = [_operation_from_data(item, index) for index, item in enumerate(operations_value)]
    _validate_operations(operations, result.commands)
    derived = _derive_session_status(operations)
    if status is not derived:
        raise SessionError("Session status does not match its operation states.")
    return ScanSession(
        session_id=session_id,
        created_at=created_at,
        target_repository=target_repository,
        backend=backend,
        status=status,
        result=result,
        operations=operations,
        schema_version=version,
    )


def _migrate_v1_session(value: object) -> object:
    """Read schema v1 without transferring its requests any approval authority."""
    if not isinstance(value, dict):
        return value
    version = value.get("schema_version")
    if version != 1:
        return value
    migrated = deepcopy(value)
    operations = migrated.get("operations")
    scan = migrated.get("scan")
    commands = scan.get("commands") if isinstance(scan, dict) else None
    if not isinstance(operations, list) or not isinstance(commands, list):
        return migrated
    for operation in operations:
        if not isinstance(operation, dict):
            continue
        if operation.get("status") == OperationStatus.PENDING.value:
            operation["status"] = OperationStatus.UNKNOWN.value
        operation.update(
            {
                "toolhub_outcome": None,
                "resume_tool": None,
                "expires_at": None,
                "trace_id": None,
            }
        )
    for command in commands:
        if not isinstance(command, dict):
            continue
        if command.get("approval_required"):
            command["approval_required"] = False
            command["toolhub_approval_status"] = None
            detail = "Schema-v1 request is non-resumable under Contract V1."
            command["message"] = f"{detail} {command.get('message', '')}".strip()
        command.update(
            {
                "toolhub_outcome": None,
                "resume_tool": None,
                "expires_at": None,
                "trace_id": None,
                "error_code": None,
                "error_retryable": None,
            }
        )
    statuses = [item.get("status") for item in operations if isinstance(item, dict)]
    migrated["status"] = (
        SessionStatus.COMPLETED.value
        if statuses and all(item == OperationStatus.COMPLETED.value for item in statuses)
        else SessionStatus.UNABLE_TO_CONTINUE.value
    )
    migrated["schema_version"] = SESSION_SCHEMA_VERSION
    return migrated


def _scan_from_data(value: object, target: Path) -> ScanResult:
    data = _object(
        value,
        "scan",
        {
            "technologies",
            "files",
            "lines",
            "inspected_files",
            "commands",
            "potential_bugs",
            "maintainability_issues",
            "deterministic_score",
            "score",
            "ai_requested",
            "ai_findings",
            "ai_error",
            "ai_context_files",
        },
    )
    commands_value = data["commands"]
    findings_value = data["ai_findings"]
    if not isinstance(commands_value, list) or not isinstance(findings_value, list):
        raise SessionError("scan commands and ai_findings must be lists.")
    ai_error = data["ai_error"]
    if ai_error is not None:
        ai_error = _text(ai_error, "scan.ai_error", max_length=MAX_PERSISTED_OUTPUT_CHARS)
    return ScanResult(
        path=target,
        technologies=_text_list(data["technologies"], "scan.technologies"),
        files=_nonnegative_integer(data["files"], "scan.files"),
        lines=_nonnegative_integer(data["lines"], "scan.lines"),
        inspected_files=_text_list(data["inspected_files"], "scan.inspected_files"),
        commands=[_command_from_data(item, index) for index, item in enumerate(commands_value)],
        potential_bugs=_text_list(data["potential_bugs"], "scan.potential_bugs"),
        maintainability_issues=_text_list(
            data["maintainability_issues"], "scan.maintainability_issues"
        ),
        deterministic_score=_score(data["deterministic_score"], "deterministic_score"),
        score=_score(data["score"], "score"),
        ai_requested=_boolean(data["ai_requested"], "scan.ai_requested"),
        ai_findings=[_finding_from_data(item, index) for index, item in enumerate(findings_value)],
        ai_error=ai_error,
        ai_context_files=_text_list(data["ai_context_files"], "scan.ai_context_files"),
    )


def _command_from_data(value: object, index: int) -> CommandResult:
    label = f"scan.commands[{index}]"
    data = _object(
        value,
        label,
        {
            "name",
            "command",
            "exit_code",
            "stdout",
            "stderr",
            "duration",
            "timed_out",
            "executed",
            "approval_required",
            "request_id",
            "toolhub_approval_status",
            "message",
            "toolhub_outcome",
            "resume_tool",
            "expires_at",
            "trace_id",
            "error_code",
            "error_retryable",
        },
    )
    status = data["toolhub_approval_status"]
    if status is not None:
        status = _text(status, f"{label}.toolhub_approval_status")
        if status not in {"PENDING", "APPROVED", "REJECTED", "EXPIRED", "CONSUMED"}:
            raise SessionError(f"{label}.toolhub_approval_status is invalid.")
    request_id = data["request_id"]
    if request_id is not None:
        request_id = _request_id(request_id, f"{label}.request_id")
    duration = data["duration"]
    if isinstance(duration, bool) or not isinstance(duration, (int, float)):
        raise SessionError(f"{label}.duration must be a non-negative finite number.")
    duration = float(duration)
    if duration < 0 or not math.isfinite(duration):
        raise SessionError(f"{label}.duration must be a non-negative finite number.")
    outcome = data["toolhub_outcome"]
    if outcome is not None:
        try:
            outcome = ContractOutcome(_text(outcome, f"{label}.toolhub_outcome")).value
        except ValueError as error:
            raise SessionError(f"{label}.toolhub_outcome is invalid.") from error
    error_retryable = data["error_retryable"]
    if error_retryable is not None:
        error_retryable = _boolean(error_retryable, f"{label}.error_retryable")
    return CommandResult(
        name=_text(data["name"], f"{label}.name"),
        command=tuple(_text_list(data["command"], f"{label}.command")),
        exit_code=_integer(data["exit_code"], f"{label}.exit_code"),
        stdout=_text(data["stdout"], f"{label}.stdout", max_length=MAX_PERSISTED_OUTPUT_CHARS),
        stderr=_text(data["stderr"], f"{label}.stderr", max_length=MAX_PERSISTED_OUTPUT_CHARS),
        duration=duration,
        timed_out=_boolean(data["timed_out"], f"{label}.timed_out"),
        approval_required=_boolean(data["approval_required"], f"{label}.approval_required"),
        request_id=request_id,
        approval_status=status,
        message=_text(data["message"], f"{label}.message", max_length=MAX_PERSISTED_OUTPUT_CHARS),
        executed=_boolean(data["executed"], f"{label}.executed"),
        trace_id=_optional_text(data["trace_id"], f"{label}.trace_id"),
        toolhub_outcome=outcome,
        resume_tool=_optional_text(data["resume_tool"], f"{label}.resume_tool"),
        expires_at=_optional_timestamp(data["expires_at"], f"{label}.expires_at"),
        error_code=_optional_text(data["error_code"], f"{label}.error_code"),
        error_retryable=error_retryable,
    )


def _operation_from_data(value: object, index: int) -> ApprovalOperation:
    label = f"operations[{index}]"
    data = _object(
        value,
        label,
        {
            "operation_id",
            "verification_kind",
            "request_id",
            "status",
            "command_index",
            "name",
            "command",
            "toolhub_outcome",
            "resume_tool",
            "expires_at",
            "trace_id",
        },
    )
    try:
        status = OperationStatus(_text(data["status"], f"{label}.status"))
    except ValueError as error:
        raise SessionError(f"{label}.status is invalid.") from error
    kind = _text(data["verification_kind"], f"{label}.verification_kind")
    if kind not in {"tests", "lint", "other"}:
        raise SessionError(f"{label}.verification_kind is invalid.")
    return ApprovalOperation(
        operation_id=_text(data["operation_id"], f"{label}.operation_id"),
        verification_kind=kind,
        request_id=_request_id(data["request_id"], f"{label}.request_id"),
        status=status,
        command_index=_nonnegative_integer(data["command_index"], f"{label}.command_index"),
        name=_text(data["name"], f"{label}.name"),
        command=tuple(_text_list(data["command"], f"{label}.command")),
        toolhub_outcome=_optional_outcome(data["toolhub_outcome"], f"{label}.toolhub_outcome"),
        resume_tool=_optional_text(data["resume_tool"], f"{label}.resume_tool"),
        expires_at=_optional_timestamp(data["expires_at"], f"{label}.expires_at"),
        trace_id=_optional_text(data["trace_id"], f"{label}.trace_id"),
    )


def _validate_operations(
    operations: list[ApprovalOperation], commands: list[CommandResult]
) -> None:
    indexes: set[int] = set()
    ids: set[str] = set()
    for operation in operations:
        if operation.command_index >= len(commands):
            raise SessionError("Operation command_index is outside the scan command list.")
        if operation.command_index in indexes or operation.operation_id in ids:
            raise SessionError("Session operations must have unique IDs and command indexes.")
        indexes.add(operation.command_index)
        ids.add(operation.operation_id)
        command = commands[operation.command_index]
        if (
            operation.request_id != command.request_id
            or operation.name != command.name
            or operation.command != command.command
            or operation.trace_id != command.trace_id
        ):
            raise SessionError("Operation metadata does not match its scan command.")
        if operation.resume_tool is not None:
            _expected_resume_tool(operation.resume_tool, "shell.run")
        if operation.status is OperationStatus.PENDING:
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
                or command.executed
            ):
                raise SessionError("Pending operation lacks valid Contract V1 approval metadata.")
            if operation.toolhub_outcome != command.toolhub_outcome:
                raise SessionError("Pending operation outcome does not match its command result.")
            if (
                operation.toolhub_outcome
                in {
                    ContractOutcome.APPROVAL_REQUIRED.value,
                    ContractOutcome.APPROVAL_PENDING.value,
                }
                and command.approval_status != "PENDING"
            ):
                raise SessionError("Pending ToolHub outcome must retain PENDING approval state.")
            if (
                operation.toolhub_outcome == ContractOutcome.APPROVAL_APPROVED.value
                and command.approval_status != "APPROVED"
            ):
                raise SessionError("Approved ToolHub status is inconsistent in the session.")
        if operation.status is OperationStatus.COMPLETED and not command.executed:
            raise SessionError("Completed operation does not contain an executed result.")
        if operation.status not in {OperationStatus.PENDING, OperationStatus.COMPLETED} and (
            command.executed or command.approval_required
        ):
            raise SessionError("Terminal operation contains an inconsistent command result.")


def _finding_from_data(value: object, index: int) -> SemanticFinding:
    label = f"scan.ai_findings[{index}]"
    keys = {
        "id",
        "title",
        "category",
        "severity",
        "confidence",
        "file",
        "line_start",
        "line_end",
        "explanation",
        "evidence",
        "suggested_fix",
    }
    data = _object(value, label, keys)
    try:
        severity = Severity(_text(data["severity"], f"{label}.severity"))
    except ValueError as error:
        raise SessionError(f"{label}.severity is invalid.") from error
    confidence = data["confidence"]
    if isinstance(confidence, bool) or not isinstance(confidence, (int, float)):
        raise SessionError(f"{label}.confidence must be a finite number from 0 to 1.")
    confidence = float(confidence)
    if not math.isfinite(confidence) or not 0 <= confidence <= 1:
        raise SessionError(f"{label}.confidence must be a finite number from 0 to 1.")
    line_start = _nonnegative_integer(data["line_start"], f"{label}.line_start")
    line_end = _nonnegative_integer(data["line_end"], f"{label}.line_end")
    if line_start < 1 or line_end < line_start:
        raise SessionError(f"{label} has an invalid line range.")
    return SemanticFinding(
        id=_text(data["id"], f"{label}.id"),
        title=_text(data["title"], f"{label}.title"),
        category=_text(data["category"], f"{label}.category"),
        severity=severity,
        confidence=confidence,
        file=_text(data["file"], f"{label}.file"),
        line_start=line_start,
        line_end=line_end,
        explanation=_text(data["explanation"], f"{label}.explanation"),
        evidence=_text(data["evidence"], f"{label}.evidence"),
        suggested_fix=_text(data["suggested_fix"], f"{label}.suggested_fix"),
    )


def _object(value: object, label: str, keys: set[str]) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != keys:
        raise SessionError(f"{label} has missing or unexpected fields.")
    return value


def _text(value: object, label: str, *, max_length: int = 20_000) -> str:
    if not isinstance(value, str) or len(value) > max_length or "\x00" in value:
        raise SessionError(f"{label} must be bounded text without null bytes.")
    return value


def _required_text(value: object, label: str) -> str:
    text = _text(value, label)
    if not text:
        raise SessionError(f"{label} must be non-empty text.")
    return text


def _optional_text(value: object, label: str) -> str | None:
    return None if value is None else _text(value, label)


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


def _expected_resume_tool(value: object, initial_tool: str) -> str:
    expected = expected_resume_tool(initial_tool)
    if value != expected:
        raise SessionError(f"Approval handle resume_tool must be {expected!r} for {initial_tool}.")
    return expected


def _text_list(value: object, label: str) -> list[str]:
    if not isinstance(value, list) or len(value) > 10_000:
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


def _score(value: object, label: str) -> int:
    number = _integer(value, f"scan.{label}")
    if not 0 <= number <= 100:
        raise SessionError(f"scan.{label} must be between 0 and 100.")
    return number


def _boolean(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise SessionError(f"{label} must be a boolean.")
    return value
