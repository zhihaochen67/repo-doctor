from types import SimpleNamespace

import pytest

from repo_doctor.backends import _tool_payload
from repo_doctor.toolhub_contract import (
    ContractOutcome,
    ContractValidationError,
    parse_capabilities,
    parse_contract_response,
    parse_request_status,
)

EXPIRES_AT = "2099-01-01T00:00:00Z"


def capabilities(version: str = "1.0") -> dict:
    return {
        "contract_version": version,
        "package_version": "99.0.0-independent",
        "transport": "stdio",
        "approval_model": {
            "human_only": True,
            "out_of_band": True,
            "atomic": True,
            "single_use": True,
            "expiring": True,
            "status_tool": "toolhub.request_status",
        },
        "approval_operations": [
            {
                "initial_tool": "filesystem.apply_patch",
                "resume_tool": "filesystem.apply_patch_approved",
            },
            {
                "initial_tool": "filesystem.write_file",
                "resume_tool": "filesystem.write_file_approved",
            },
            {
                "initial_tool": "shell.run",
                "resume_tool": "shell.run_approved",
            },
        ],
        "limits": {
            "max_read_file_bytes": 1_000_000,
            "max_write_bytes": 1_000_000,
            "max_patch_chars": 200_000,
            "max_shell_timeout_seconds": 600,
            "shell_output_retained_chars": 100_000,
            "git_output_retained_chars": 200_000,
            "max_audit_events": 1_000,
        },
        "future_extension": {"accepted": True},
    }


def approval(status: str, *, resume_tool: str = "shell.run_approved") -> dict:
    return {
        "request_id": "req_1",
        "status": status,
        "expires_at": EXPIRES_AT,
        "resume_tool": resume_tool,
    }


def response(outcome: str) -> dict:
    statuses = {
        "APPROVAL_REQUIRED": "PENDING",
        "APPROVAL_PENDING": "PENDING",
        "APPROVAL_APPROVED": "APPROVED",
        "APPROVAL_REJECTED": "REJECTED",
        "APPROVAL_EXPIRED": "EXPIRED",
        "APPROVAL_CONSUMED": "CONSUMED",
    }
    status = statuses.get(outcome)
    final = outcome in {
        "SUCCEEDED",
        "COMMAND_FAILED",
        "TIMED_OUT",
        "CONFLICT",
        "REFUSED",
        "FAILED",
    }
    return {
        "outcome": outcome,
        "trace_id": "trc_1",
        "approval": approval(status) if status else None,
        "error": (
            None
            if outcome in {"APPROVAL_REQUIRED", "APPROVAL_APPROVED", "SUCCEEDED"}
            else {
                "code": outcome,
                "message": "diagnostic only",
                "retryable": outcome == "APPROVAL_PENDING",
            }
        ),
        "message": "human text is not authority" if final else "",
    }


@pytest.mark.parametrize("version", ["1.0", "1.7"])
def test_contract_v1_capabilities_accept_compatible_minor_versions(version: str) -> None:
    parsed = parse_capabilities(capabilities(version))

    assert parsed.contract_version == version
    assert parsed.package_version == "99.0.0-independent"
    assert parsed.resume_tool_for("shell.run") == "shell.run_approved"


def test_capabilities_reject_unsupported_major_and_malformed_payload() -> None:
    with pytest.raises(ContractValidationError, match="major version 2"):
        parse_capabilities(capabilities("2.0"))
    with pytest.raises(ContractValidationError, match="must be an object"):
        parse_capabilities([])
    malformed = capabilities()
    malformed["approval_model"] = {"human_only": True}
    with pytest.raises(ContractValidationError, match="out_of_band"):
        parse_capabilities(malformed)


def test_capabilities_reject_missing_and_unsafe_operation_mappings() -> None:
    missing = capabilities()
    missing["approval_operations"] = missing["approval_operations"][:-1]
    with pytest.raises(ContractValidationError, match="omit.*shell.run"):
        parse_capabilities(missing)

    unsafe = capabilities()
    unsafe["approval_operations"][-1]["resume_tool"] = "shell.evil"
    with pytest.raises(ContractValidationError, match="Unsafe.*shell.run"):
        parse_capabilities(unsafe)


@pytest.mark.parametrize("field", ["package_version", "limits"])
def test_capabilities_require_production_metadata(field: str) -> None:
    payload = capabilities()
    payload.pop(field)

    with pytest.raises(ContractValidationError, match=f"required fields.*{field}"):
        parse_capabilities(payload)


@pytest.mark.parametrize("package_version", [None, "", "x" * 129, "bad\x00version"])
def test_capabilities_reject_malformed_package_version(package_version: object) -> None:
    payload = capabilities()
    payload["package_version"] = package_version

    with pytest.raises(ContractValidationError, match="package_version"):
        parse_capabilities(payload)


@pytest.mark.parametrize("value", [True, "100", 0, -1, 2_147_483_648])
def test_capabilities_reject_invalid_required_limits(value: object) -> None:
    payload = capabilities()
    payload["limits"]["max_patch_chars"] = value

    with pytest.raises(ContractValidationError, match="limits.max_patch_chars"):
        parse_capabilities(payload)


def test_capabilities_reject_missing_or_unexpected_limit_fields() -> None:
    missing = capabilities()
    missing["limits"].pop("max_audit_events")
    with pytest.raises(ContractValidationError, match="missing max_audit_events"):
        parse_capabilities(missing)

    unexpected = capabilities()
    unexpected["limits"]["unpublished_limit"] = 1
    with pytest.raises(ContractValidationError, match="unexpected unpublished_limit"):
        parse_capabilities(unexpected)


def test_contract_lifecycle_never_falls_back_to_json_text() -> None:
    result = SimpleNamespace(
        is_error=False,
        structured_content=None,
        content=[SimpleNamespace(type="text", text='{"outcome":"SUCCEEDED"}')],
    )

    with pytest.raises(RuntimeError, match="no structuredContent.*does not permit"):
        _tool_payload(result)


@pytest.mark.parametrize("outcome", [item.value for item in ContractOutcome])
def test_every_contract_v1_outcome_has_a_strict_local_model(outcome: str) -> None:
    parsed = parse_contract_response(response(outcome), call="test.operation")

    assert parsed.outcome.value == outcome
    assert parsed.trace_id == "trc_1"


def test_contradictory_approval_payload_is_rejected() -> None:
    payload = response("APPROVAL_APPROVED")
    payload["approval"]["status"] = "PENDING"

    with pytest.raises(ContractValidationError, match="requires.*APPROVED"):
        parse_contract_response(payload, call="shell.run_approved")


@pytest.mark.parametrize(
    "error",
    [
        {"code": "lowercase", "message": "bad", "retryable": False},
        {"code": "BAD-CODE", "message": "bad", "retryable": False},
        {"code": "A" * 81, "message": "bad", "retryable": False},
        {"code": "FAILED", "message": "x" * 501, "retryable": False},
        {"code": "FAILED", "message": "bad", "retryable": 1},
        {"code": "FAILED", "message": "bad", "retryable": False, "extra": True},
        {"code": "FAILED", "message": "bad"},
    ],
)
def test_contract_error_matches_strict_production_shape(error: dict) -> None:
    payload = response("FAILED")
    payload["error"] = error

    with pytest.raises(ContractValidationError, match="error"):
        parse_contract_response(payload, call="test.operation")


def test_approval_handle_rejects_unexpected_structure() -> None:
    payload = response("APPROVAL_PENDING")
    payload["approval"]["approved"] = True

    with pytest.raises(ContractValidationError, match="approval.*unexpected"):
        parse_contract_response(payload, call="toolhub.request_status")


def test_request_status_validates_request_id_and_allowed_outcomes() -> None:
    pending = response("APPROVAL_PENDING")
    pending["request_id"] = "req_1"
    assert parse_request_status(pending, request_id="req_1").outcome is (
        ContractOutcome.APPROVAL_PENDING
    )

    pending["request_id"] = "req_other"
    with pytest.raises(ContractValidationError, match="different approval request ID"):
        parse_request_status(pending, request_id="req_1")

    invalid = response("SUCCEEDED")
    invalid["request_id"] = "req_1"
    with pytest.raises(ContractValidationError, match="invalid outcome"):
        parse_request_status(invalid, request_id="req_1")
