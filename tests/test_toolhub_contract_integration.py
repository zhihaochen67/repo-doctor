"""Opt-in real-process coverage for the ToolHub Contract V1 lifecycle."""

from __future__ import annotations

import hashlib
import os
import subprocess
from pathlib import Path

import pytest

from repo_doctor.backends import MCPToolBackend
from repo_doctor.repair_sessions import (
    RepairOperationKind,
    RepairPhase,
    VerificationPlan,
    load_repair_session,
    new_repair_session,
    record_patch_request,
    resume_repair_session,
    save_repair_session,
)
from repo_doctor.toolhub_contract import ContractOutcome


def _toolhub_binaries() -> tuple[Path, Path, Path]:
    project = Path(r"D:\mcp-toolhub")
    if os.name == "nt":
        python = project / ".venv" / "Scripts" / "python.exe"
        admin = project / ".venv" / "Scripts" / "mcp-toolhub-admin.exe"
    else:
        python = project / ".venv" / "bin" / "python"
        admin = project / ".venv" / "bin" / "mcp-toolhub-admin"
    return project, python, admin


def _admin_decide(
    admin: Path,
    project: Path,
    repository: Path,
    state_root: Path,
    request_id: str,
    decision: str,
) -> None:
    environment = os.environ.copy()
    environment["TOOLHUB_WORKSPACE_ROOT"] = str(repository)
    environment["TOOLHUB_STATE_ROOT"] = str(state_root)
    completed = subprocess.run(
        [str(admin), decision.casefold(), request_id],
        cwd=project,
        env=environment,
        input=f"{decision}\n",
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        shell=False,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


@pytest.mark.integration
def test_real_toolhub_contract_v1_patch_shell_reject_and_unknown(
    tmp_path: Path,
    monkeypatch,
) -> None:
    if os.environ.get("REPO_DOCTOR_RUN_TOOLHUB_INTEGRATION") != "1":
        pytest.skip("set REPO_DOCTOR_RUN_TOOLHUB_INTEGRATION=1 to run real ToolHub integration")
    toolhub, production_python, admin = _toolhub_binaries()
    if not toolhub.is_dir() or not production_python.is_file() or not admin.is_file():
        pytest.skip(r"production ToolHub executables are unavailable at D:\mcp-toolhub")
    monkeypatch.setenv("REPO_DOCTOR_TOOLHUB_PROJECT", str(toolhub.resolve()))

    repository = tmp_path / "repository"
    repository.mkdir()
    target = repository / "app.py"
    target.write_text("def value():\n    return 1\n", encoding="utf-8")
    tests = repository / "tests"
    tests.mkdir()
    (tests / "test_pass.py").write_text(
        "from app import value\n\n\ndef test_value():\n    assert value() == 2\n",
        encoding="utf-8",
    )
    (tests / "test_fail.py").write_text(
        "def test_failure():\n    assert False\n",
        encoding="utf-8",
    )
    rejected_target = repository / "rejected.py"
    rejected_target.write_text("before\n", encoding="utf-8")
    subprocess.run(["git", "init", "-q", str(repository)], check=True)
    subprocess.run(["git", "-C", str(repository), "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(repository),
            "-c",
            "user.name=repo-doctor-test",
            "-c",
            "user.email=repo-doctor-test@example.com",
            "commit",
            "-q",
            "-m",
            "initial",
        ],
        check=True,
    )

    state = tmp_path / "isolated-state"
    toolhub_state = state / "toolhub"
    repo_doctor_state = state / "repo-doctor"
    monkeypatch.setenv("TOOLHUB_STATE_ROOT", str(toolhub_state))
    monkeypatch.setenv("REPO_DOCTOR_STATE_ROOT", str(repo_doctor_state))

    original = target.read_bytes()
    patch = (
        "--- a/app.py\n+++ b/app.py\n@@ -1,2 +1,2 @@\n def value():\n-    return 1\n+    return 2\n"
    )
    session = new_repair_session(
        repository,
        finding_id="real-contract-v1",
        finding_title="Real Contract V1 mutation",
        target_file="app.py",
        expected_hash=hashlib.sha256(original).hexdigest(),
        proposed_hash=hashlib.sha256(b"def value():\n    return 2\n").hexdigest(),
        verification_plan=(
            VerificationPlan(
                "Python tests",
                ("python", "-m", "pytest", "-q", "tests/test_pass.py"),
            ),
        ),
    )

    with MCPToolBackend(repository, toolhub_project=toolhub) as backend:
        assert backend.capabilities is not None
        assert backend.capabilities.contract_version.startswith("1.")
        mutation = backend.apply_patch("app.py", patch, session.expected_hash)
        assert mutation.toolhub_outcome == ContractOutcome.APPROVAL_REQUIRED.value
        assert mutation.resume_tool == "filesystem.apply_patch_approved"
        initial_trace = mutation.trace_id
        request_id = mutation.request_id
        assert request_id is not None
        pending = backend.request_status(request_id)
        assert pending.outcome is ContractOutcome.APPROVAL_PENDING
        assert pending.trace_id == initial_trace

    record_patch_request(session, mutation)
    save_repair_session(session)
    persisted = load_repair_session(session.session_id)
    assert persisted.patch_operation is not None
    assert persisted.patch_operation.request_id == request_id
    assert persisted.patch_operation.trace_id == initial_trace
    assert "return 2" not in (
        repo_doctor_state / "sessions" / f"{session.session_id}.json"
    ).read_text(encoding="utf-8")

    _admin_decide(admin, toolhub, repository, toolhub_state, request_id, "APPROVE")
    with MCPToolBackend(repository, toolhub_project=toolhub) as backend:
        approved = backend.request_status(request_id)
        assert approved.outcome is ContractOutcome.APPROVAL_APPROVED
        assert approved.trace_id == initial_trace

    resume_repair_session(session)
    assert target.read_text(encoding="utf-8") == "def value():\n    return 2\n"
    assert session.patch_operation is not None
    assert session.patch_operation.trace_id == initial_trace
    assert session.phase is RepairPhase.VERIFICATION_PENDING
    with MCPToolBackend(repository, toolhub_project=toolhub) as backend:
        consumed = backend.request_status(request_id)
        assert consumed.outcome is ContractOutcome.APPROVAL_CONSUMED
        assert consumed.trace_id == initial_trace

    # A pending verification resume re-polls only that request; the consumed patch is not replayed.
    resume_repair_session(session)
    assert target.read_text(encoding="utf-8") == "def value():\n    return 2\n"
    verification = next(
        item for item in session.pending_operations if item.kind is RepairOperationKind.VERIFICATION
    )
    verification_trace = verification.trace_id
    assert verification.request_id is not None
    _admin_decide(
        admin,
        toolhub,
        repository,
        toolhub_state,
        verification.request_id,
        "APPROVE",
    )
    resume_repair_session(session)
    assert session.phase is RepairPhase.VERIFIED_PASS
    completed_verification = next(
        item for item in session.operations if item.kind is RepairOperationKind.VERIFICATION
    )
    assert completed_verification.toolhub_outcome == ContractOutcome.SUCCEEDED.value
    assert completed_verification.trace_id == verification_trace

    with MCPToolBackend(repository, toolhub_project=toolhub) as backend:
        failed = backend.run_command(
            "Expected failure",
            ("python", "-m", "pytest", "-q", "tests/test_fail.py"),
        )
        assert failed.toolhub_outcome == ContractOutcome.APPROVAL_REQUIRED.value
        assert failed.request_id is not None
        failed_trace = failed.trace_id
        failed_pending = backend.request_status(failed.request_id)
        assert failed_pending.outcome is ContractOutcome.APPROVAL_PENDING
    _admin_decide(admin, toolhub, repository, toolhub_state, failed.request_id, "APPROVE")
    with MCPToolBackend(repository, toolhub_project=toolhub) as backend:
        failed_approved = backend.request_status(failed.request_id)
        assert failed_approved.outcome is ContractOutcome.APPROVAL_APPROVED
        assert failed_approved.approval is not None
        failed_result = backend.run_approved(
            failed.request_id,
            name="Expected failure",
            resume_tool=failed_approved.approval.resume_tool,
        )
        assert failed_result.toolhub_outcome == ContractOutcome.COMMAND_FAILED.value
        assert failed_result.exit_code != 0
        assert failed_result.trace_id == failed_trace

    rejected_original = rejected_target.read_bytes()
    rejected_patch = "--- a/rejected.py\n+++ b/rejected.py\n@@ -1 +1 @@\n-before\n+after\n"
    with MCPToolBackend(repository, toolhub_project=toolhub) as backend:
        rejected = backend.apply_patch(
            "rejected.py",
            rejected_patch,
            hashlib.sha256(rejected_original).hexdigest(),
        )
        assert rejected.request_id is not None
    _admin_decide(admin, toolhub, repository, toolhub_state, rejected.request_id, "REJECT")
    with MCPToolBackend(repository, toolhub_project=toolhub) as backend:
        rejected_status = backend.request_status(rejected.request_id)
        assert rejected_status.outcome is ContractOutcome.APPROVAL_REJECTED
        unknown = backend.request_status("req_repo_doctor_unknown_contract_v1")
        assert unknown.outcome is ContractOutcome.REFUSED
        assert unknown.error is not None and unknown.error.code == "REQUEST_NOT_FOUND"
    assert rejected_target.read_bytes() == rejected_original
