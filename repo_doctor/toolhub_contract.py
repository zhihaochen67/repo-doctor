"""Strict, local models for the MCP ToolHub Contract V1 boundary."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

CONTRACT_MAJOR_VERSION = 1
CAPABILITIES_TOOL = "toolhub.capabilities"
REQUEST_STATUS_TOOL = "toolhub.request_status"
EXPECTED_RESUME_TOOLS = {
    "shell.run": "shell.run_approved",
    "filesystem.apply_patch": "filesystem.apply_patch_approved",
}

_CONTRACT_VERSION = re.compile(r"(?P<major>0|[1-9][0-9]*)\.(?P<minor>0|[1-9][0-9]*)")
_TOOL_NAME = re.compile(r"[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*)+")
_ERROR_CODE = re.compile(r"[A-Z][A-Z0-9_]{0,79}")
_LIFECYCLE_APPROVAL_STATUS: dict[ContractOutcome, ApprovalStatus]
_LIMIT_FIELDS = (
    "max_read_file_bytes",
    "max_write_bytes",
    "max_patch_chars",
    "max_shell_timeout_seconds",
    "shell_output_retained_chars",
    "git_output_retained_chars",
    "max_audit_events",
)


class ContractValidationError(ValueError):
    """ToolHub returned a malformed or incompatible Contract V1 payload."""


class ContractOutcome(StrEnum):
    """Every machine outcome defined by ToolHub Contract V1."""

    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    APPROVAL_PENDING = "APPROVAL_PENDING"
    APPROVAL_APPROVED = "APPROVAL_APPROVED"
    APPROVAL_REJECTED = "APPROVAL_REJECTED"
    APPROVAL_EXPIRED = "APPROVAL_EXPIRED"
    APPROVAL_CONSUMED = "APPROVAL_CONSUMED"
    SUCCEEDED = "SUCCEEDED"
    COMMAND_FAILED = "COMMAND_FAILED"
    TIMED_OUT = "TIMED_OUT"
    CONFLICT = "CONFLICT"
    REFUSED = "REFUSED"
    FAILED = "FAILED"


class ApprovalStatus(StrEnum):
    """Server-owned states carried by an approval handle."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CONSUMED = "CONSUMED"


_LIFECYCLE_APPROVAL_STATUS = {
    ContractOutcome.APPROVAL_REQUIRED: ApprovalStatus.PENDING,
    ContractOutcome.APPROVAL_PENDING: ApprovalStatus.PENDING,
    ContractOutcome.APPROVAL_APPROVED: ApprovalStatus.APPROVED,
    ContractOutcome.APPROVAL_REJECTED: ApprovalStatus.REJECTED,
    ContractOutcome.APPROVAL_EXPIRED: ApprovalStatus.EXPIRED,
    ContractOutcome.APPROVAL_CONSUMED: ApprovalStatus.CONSUMED,
}


@dataclass(frozen=True)
class ContractError:
    code: str
    message: str
    retryable: bool


@dataclass(frozen=True)
class ApprovalHandle:
    request_id: str
    status: ApprovalStatus
    expires_at: str
    resume_tool: str


@dataclass(frozen=True)
class ContractResponse:
    outcome: ContractOutcome
    trace_id: str
    approval: ApprovalHandle | None
    error: ContractError | None
    message: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class RequestStatusResult:
    request_id: str
    outcome: ContractOutcome
    trace_id: str
    approval: ApprovalHandle | None
    error: ContractError | None


@dataclass(frozen=True)
class ToolHubLimits:
    max_read_file_bytes: int
    max_write_bytes: int
    max_patch_chars: int
    max_shell_timeout_seconds: int
    shell_output_retained_chars: int
    git_output_retained_chars: int
    max_audit_events: int


@dataclass(frozen=True)
class ToolHubCapabilities:
    contract_version: str
    package_version: str
    transport: str
    operation_mappings: tuple[tuple[str, str], ...]
    limits: ToolHubLimits

    def resume_tool_for(self, initial_tool: str) -> str:
        for declared_initial, resume_tool in self.operation_mappings:
            if declared_initial == initial_tool:
                return resume_tool
        raise ContractValidationError(
            f"ToolHub capabilities omit the required operation mapping for {initial_tool}."
        )

    @property
    def allowed_resume_tools(self) -> frozenset[str]:
        return frozenset(resume for _, resume in self.operation_mappings)


def parse_capabilities(payload: object) -> ToolHubCapabilities:
    """Validate the authoritative capabilities response and compatibility policy."""
    data = _object(payload, "toolhub.capabilities")
    required_fields = {
        "contract_version",
        "package_version",
        "transport",
        "approval_model",
        "approval_operations",
        "limits",
    }
    missing_fields = sorted(required_fields.difference(data))
    if missing_fields:
        raise ContractValidationError(
            "toolhub.capabilities omits required fields: " + ", ".join(missing_fields) + "."
        )
    version = _text(data.get("contract_version"), "contract_version", limit=32)
    match = _CONTRACT_VERSION.fullmatch(version)
    if match is None:
        raise ContractValidationError("contract_version must use the '<major>.<minor>' form.")
    major = int(match.group("major"))
    if major != CONTRACT_MAJOR_VERSION:
        raise ContractValidationError(
            f"Unsupported ToolHub contract major version {major}; Contract V1 is required."
        )
    transport = _text(data.get("transport"), "transport", limit=32)
    if transport != "stdio":
        raise ContractValidationError(
            f"ToolHub Contract V1 requires stdio transport, got {transport!r}."
        )

    approval_model = _object(data.get("approval_model"), "approval_model")
    expected_approval_fields = {
        "human_only",
        "out_of_band",
        "atomic",
        "single_use",
        "expiring",
        "status_tool",
    }
    if set(approval_model) != expected_approval_fields:
        missing = sorted(expected_approval_fields.difference(approval_model))
        unexpected = sorted(set(approval_model).difference(expected_approval_fields))
        details = []
        if missing:
            details.append("missing " + ", ".join(missing))
        if unexpected:
            details.append("unexpected " + ", ".join(unexpected))
        raise ContractValidationError(
            "approval_model has invalid fields: " + "; ".join(details) + "."
        )
    for field in ("human_only", "out_of_band", "atomic", "single_use", "expiring"):
        if approval_model.get(field) is not True:
            raise ContractValidationError(f"approval_model.{field} must be true.")
    if approval_model.get("status_tool") != REQUEST_STATUS_TOOL:
        raise ContractValidationError(
            f"approval_model.status_tool must be {REQUEST_STATUS_TOOL!r}."
        )

    operations = data.get("approval_operations")
    if not isinstance(operations, list) or not operations or len(operations) > 100:
        raise ContractValidationError("approval_operations must be a bounded non-empty list.")
    declared: dict[str, str] = {}
    for index, item in enumerate(operations):
        operation = _object(item, f"approval_operations[{index}]")
        if set(operation) != {"initial_tool", "resume_tool"}:
            raise ContractValidationError(
                f"approval_operations[{index}] has missing or unexpected fields."
            )
        initial = _tool_name(operation.get("initial_tool"), f"approval_operations[{index}]")
        resume = _tool_name(operation.get("resume_tool"), f"approval_operations[{index}]")
        previous = declared.setdefault(initial, resume)
        if previous != resume:
            raise ContractValidationError(
                f"ToolHub declares conflicting resume tools for {initial}."
            )

    for initial, expected_resume in EXPECTED_RESUME_TOOLS.items():
        actual = declared.get(initial)
        if actual is None:
            raise ContractValidationError(
                f"ToolHub capabilities omit the required operation mapping for {initial}."
            )
        if actual != expected_resume:
            raise ContractValidationError(
                f"Unsafe ToolHub resume mapping for {initial}: expected "
                f"{expected_resume!r}, got {actual!r}."
            )

    limits_data = _object(data.get("limits"), "limits")
    missing_limits = sorted(set(_LIMIT_FIELDS).difference(limits_data))
    unexpected_limits = sorted(set(limits_data).difference(_LIMIT_FIELDS))
    if missing_limits or unexpected_limits:
        details = []
        if missing_limits:
            details.append("missing " + ", ".join(missing_limits))
        if unexpected_limits:
            details.append("unexpected " + ", ".join(unexpected_limits))
        raise ContractValidationError("limits has invalid fields: " + "; ".join(details) + ".")
    limit_values = {
        field: _positive_integer(limits_data[field], f"limits.{field}") for field in _LIMIT_FIELDS
    }

    package_version = _text(data.get("package_version"), "package_version", limit=128)
    if not package_version or any(ord(character) < 32 for character in package_version):
        raise ContractValidationError("package_version must be non-empty printable text.")
    return ToolHubCapabilities(
        contract_version=version,
        package_version=package_version,
        transport=transport,
        operation_mappings=tuple((name, declared[name]) for name in EXPECTED_RESUME_TOOLS),
        limits=ToolHubLimits(**limit_values),
    )


def parse_contract_response(payload: object, *, call: str) -> ContractResponse:
    """Parse common Contract V1 response metadata without consulting human prose."""
    data = _object(payload, f"{call} result")
    try:
        outcome = ContractOutcome(_text(data.get("outcome"), "outcome", limit=64))
    except ValueError as error:
        raise ContractValidationError(
            f"{call} returned an unsupported Contract V1 outcome."
        ) from error
    trace_id = _identifier(data.get("trace_id"), "trace_id")
    approval = _approval(data.get("approval"))
    contract_error = _error(data.get("error"))
    message_value = data.get("message", "")
    message = _text(message_value, "message", limit=20_000)

    expected_status = _LIFECYCLE_APPROVAL_STATUS.get(outcome)
    if expected_status is not None:
        if approval is None or approval.status is not expected_status:
            raise ContractValidationError(
                f"{outcome.value} requires an approval handle in {expected_status.value} state."
            )
    elif approval is not None and approval.status is not ApprovalStatus.CONSUMED:
        raise ContractValidationError(
            f"Final outcome {outcome.value} cannot carry a non-consumed approval handle."
        )
    if (
        outcome
        in {
            ContractOutcome.SUCCEEDED,
            ContractOutcome.APPROVAL_REQUIRED,
            ContractOutcome.APPROVAL_APPROVED,
        }
        and contract_error is not None
    ):
        raise ContractValidationError(f"{outcome.value} cannot carry an error object.")

    return ContractResponse(
        outcome=outcome,
        trace_id=trace_id,
        approval=approval,
        error=contract_error,
        message=message,
        payload=data,
    )


def parse_request_status(payload: object, *, request_id: str) -> RequestStatusResult:
    """Validate one toolhub.request_status response."""
    expected_request_id = _identifier(request_id, "request_id")
    response = parse_contract_response(payload, call=REQUEST_STATUS_TOOL)
    allowed = {
        ContractOutcome.APPROVAL_PENDING,
        ContractOutcome.APPROVAL_APPROVED,
        ContractOutcome.APPROVAL_REJECTED,
        ContractOutcome.APPROVAL_EXPIRED,
        ContractOutcome.APPROVAL_CONSUMED,
        ContractOutcome.REFUSED,
    }
    if response.outcome not in allowed:
        raise ContractValidationError(
            f"toolhub.request_status returned invalid outcome {response.outcome.value}."
        )
    returned_request_id = _identifier(response.payload.get("request_id"), "request_id")
    if returned_request_id != expected_request_id:
        raise ContractValidationError("ToolHub returned a different approval request ID.")
    if response.approval is not None and response.approval.request_id != expected_request_id:
        raise ContractValidationError("ToolHub approval handle has a different request ID.")
    return RequestStatusResult(
        request_id=returned_request_id,
        outcome=response.outcome,
        trace_id=response.trace_id,
        approval=response.approval,
        error=response.error,
    )


def expected_resume_tool(initial_tool: str) -> str:
    try:
        return EXPECTED_RESUME_TOOLS[initial_tool]
    except KeyError as error:
        raise ContractValidationError(
            f"Repo Doctor does not resume operation {initial_tool!r}."
        ) from error


def _approval(value: object) -> ApprovalHandle | None:
    if value is None:
        return None
    data = _object(value, "approval")
    if set(data) != {"request_id", "status", "expires_at", "resume_tool"}:
        raise ContractValidationError("approval has missing or unexpected fields.")
    request_id = _identifier(data.get("request_id"), "approval.request_id")
    try:
        status = ApprovalStatus(_text(data.get("status"), "approval.status", limit=32))
    except ValueError as error:
        raise ContractValidationError("approval.status is invalid.") from error
    expires_at = _text(data.get("expires_at"), "approval.expires_at", limit=128)
    try:
        parsed = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
    except ValueError as error:
        raise ContractValidationError(
            "approval.expires_at must be an ISO-8601 timestamp."
        ) from error
    if parsed.tzinfo is None:
        raise ContractValidationError("approval.expires_at must include a timezone.")
    resume_tool = _tool_name(data.get("resume_tool"), "approval.resume_tool")
    return ApprovalHandle(request_id, status, expires_at, resume_tool)


def _error(value: object) -> ContractError | None:
    if value is None:
        return None
    data = _object(value, "error")
    if set(data) != {"code", "message", "retryable"}:
        raise ContractValidationError("error has missing or unexpected fields.")
    code = _text(data.get("code"), "error.code", limit=80)
    if _ERROR_CODE.fullmatch(code) is None:
        raise ContractValidationError(
            "error.code must be an uppercase stable code of at most 80 characters."
        )
    message = _text(data.get("message"), "error.message", limit=500)
    retryable = data.get("retryable")
    if not isinstance(retryable, bool):
        raise ContractValidationError("error.retryable must be a boolean.")
    return ContractError(code, message, retryable)


def _object(value: object, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ContractValidationError(f"{label} must be an object.")
    return value


def _text(value: object, label: str, *, limit: int) -> str:
    if not isinstance(value, str) or len(value) > limit or "\x00" in value:
        raise ContractValidationError(f"{label} must be bounded text without null bytes.")
    return value


def _identifier(value: object, label: str) -> str:
    text = _text(value, label, limit=512)
    if not text or any(ord(character) < 32 for character in text):
        raise ContractValidationError(f"{label} must be non-empty printable text.")
    return text


def _positive_integer(value: object, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= 2_147_483_647:
        raise ContractValidationError(f"{label} must be a positive bounded integer.")
    return value


def _tool_name(value: object, label: str) -> str:
    name = _text(value, label, limit=128)
    if _TOOL_NAME.fullmatch(name) is None:
        raise ContractValidationError(f"{label} is not a safe MCP tool name.")
    return name
