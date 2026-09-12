import hashlib
import json
import os
import subprocess
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from repo_doctor.ai.errors import PatchValidationError
from repo_doctor.ai.mcp_fixer import execute_mcp_ai_fix
from repo_doctor.ai.models import AnalysisResponse, PatchProposal, SemanticFinding, Severity
from repo_doctor.ai.patching import prepare_patch_from_content
from repo_doctor.backends import (
    MCPToolBackend,
    MutationConflictError,
    ToolBackendKind,
    ToolCallError,
)
from repo_doctor.cli import app
from repo_doctor.models import (
    CommandResult,
    FileReadResult,
    GitDiffResult,
    GitStatusResult,
    PatchMutationResult,
)
from repo_doctor.repair_sessions import (
    RepairOperationKind,
    RepairOperationStatus,
    RepairPhase,
    VerificationPlan,
    load_repair_session,
    new_repair_session,
    record_patch_request,
    resume_repair_session,
    save_repair_session,
)
from repo_doctor.sessions import SessionError, session_file_path
from repo_doctor.toolhub_contract import (
    ApprovalHandle,
    ApprovalStatus,
    ContractError,
    ContractOutcome,
    RequestStatusResult,
)

EXPIRES_AT = "2099-01-01T00:00:00Z"


def prepare_toolhub_project(project: Path) -> Path:
    interpreter = (
        project / ".venv" / "Scripts" / "python.exe"
        if os.name == "nt"
        else project / ".venv" / "bin" / "python"
    )
    interpreter.parent.mkdir(parents=True, exist_ok=True)
    interpreter.write_bytes(b"")
    return project


def capabilities_response() -> dict:
    return {
        "contract_version": "1.0",
        "package_version": "test",
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
                "initial_tool": "shell.run",
                "resume_tool": "shell.run_approved",
            },
            {
                "initial_tool": "filesystem.apply_patch",
                "resume_tool": "filesystem.apply_patch_approved",
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
    }


class DeterministicRepairProvider:
    def __init__(self, *, old_text: str = "return requested < stock") -> None:
        self.old_text = old_text
        self.analysis_request = None
        self.patch_request = None

    def analyze(self, request):
        self.analysis_request = request
        return AnalysisResponse(
            (
                SemanticFinding(
                    "boundary-1",
                    "Exact stock is rejected",
                    "control-flow",
                    Severity.HIGH,
                    0.96,
                    "inventory.py",
                    2,
                    2,
                    "Equality must be accepted.",
                    "The comparison excludes equality.",
                    "Use <=.",
                ),
            )
        )

    def generate_patch(self, request):
        self.patch_request = request
        return PatchProposal(
            "inventory.py",
            self.old_text,
            "return requested <= stock",
            "Accept equality",
            0.97,
        )


class SharedBackendState:
    def __init__(self) -> None:
        self.calls = []
        self.roots = []
        self.patch_result = PatchMutationResult(
            path="inventory.py",
            executed=False,
            trace_id="trc_patch_request",
            request_id="req_patch",
            approval_status="PENDING",
            message="Approval required.",
            toolhub_outcome="APPROVAL_REQUIRED",
            resume_tool="filesystem.apply_patch_approved",
            expires_at=EXPIRES_AT,
        )
        self.patch_error = None
        self.approved_patch_result = PatchMutationResult(
            path="inventory.py",
            executed=True,
            changed=True,
            additions=1,
            deletions=1,
            previous_hash="1" * 64,
            new_hash="2" * 64,
            trace_id="trc_patch_request",
            request_id="req_patch",
            approval_status="CONSUMED",
            toolhub_outcome="SUCCEEDED",
            resume_tool="filesystem.apply_patch_approved",
            expires_at=EXPIRES_AT,
        )
        self.submissions = {
            "Python tests": pending_command("Python tests", ("pytest",), "req_tests"),
            "Python lint": pending_command("Python lint", ("ruff", "check", "."), "req_lint"),
        }
        self.approved_commands = {}
        self.diff = GitDiffResult(
            "inventory.py",
            False,
            1,
            1,
            False,
            "-    return requested < stock\n+    return requested <= stock\n",
        )


class FakeRepairBackend:
    verification_in_place = True

    def __init__(self, root: Path, state: SharedBackendState):
        self.root = root.resolve()
        self.state = state
        state.roots.append(self.root)

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        return None

    def read_file(self, path: str) -> FileReadResult:
        self.state.calls.append(("read_file", path))
        data = (self.root / path).read_bytes()
        return FileReadResult(path, len(data), hashlib.sha256(data).hexdigest(), data.decode())

    def git_status(self) -> GitStatusResult:
        self.state.calls.append(("git_status",))
        return GitStatusResult(".", "main", True, (), "## main\n")

    def apply_patch(self, path: str, patch: str, expected_hash: str) -> PatchMutationResult:
        self.state.calls.append(("apply_patch", path, patch, expected_hash))
        if self.state.patch_error is not None:
            raise self.state.patch_error
        return self.state.patch_result

    def request_status(self, request_id: str) -> RequestStatusResult:
        self.state.calls.append(("request_status", request_id))
        if request_id == "req_patch":
            result = self.state.approved_patch_result
            resume_tool = "filesystem.apply_patch_approved"
            trace_id = "trc_patch_request"
        else:
            result = self.state.approved_commands.get(request_id)
            if result is None:
                result = next(
                    item
                    for item in self.state.submissions.values()
                    if item.request_id == request_id
                )
            resume_tool = "shell.run_approved"
            trace_id = f"trc_{request_id}"
        if result.executed:
            outcome = ContractOutcome.APPROVAL_APPROVED
            approval_status = ApprovalStatus.APPROVED
        else:
            outcome = {
                "PENDING": ContractOutcome.APPROVAL_PENDING,
                "APPROVED": ContractOutcome.APPROVAL_APPROVED,
                "REJECTED": ContractOutcome.APPROVAL_REJECTED,
                "EXPIRED": ContractOutcome.APPROVAL_EXPIRED,
                "CONSUMED": ContractOutcome.APPROVAL_CONSUMED,
            }.get(result.approval_status, ContractOutcome.REFUSED)
            approval_status = {
                "PENDING": ApprovalStatus.PENDING,
                "APPROVED": ApprovalStatus.APPROVED,
                "REJECTED": ApprovalStatus.REJECTED,
                "EXPIRED": ApprovalStatus.EXPIRED,
                "CONSUMED": ApprovalStatus.CONSUMED,
            }.get(result.approval_status)
        approval = (
            ApprovalHandle(request_id, approval_status, EXPIRES_AT, resume_tool)
            if approval_status is not None
            else None
        )
        error = None
        if outcome is ContractOutcome.REFUSED:
            error = ContractError("REQUEST_NOT_FOUND", result.message, False)
        elif outcome not in {ContractOutcome.APPROVAL_APPROVED}:
            error = ContractError(
                outcome.value,
                result.message,
                outcome is ContractOutcome.APPROVAL_PENDING,
            )
        return RequestStatusResult(request_id, outcome, trace_id, approval, error)

    def run_approved_mutation(
        self,
        request_id: str,
        *,
        resume_tool: str | None = None,
        expected_path: str,
        expected_trace_id: str,
    ) -> PatchMutationResult:
        self.state.calls.append(("run_approved_mutation", request_id))
        assert resume_tool == "filesystem.apply_patch_approved"
        assert expected_path == "inventory.py"
        assert expected_trace_id == "trc_patch_request"
        return self.state.approved_patch_result

    def run_command(
        self,
        name: str,
        command: tuple[str, ...],
        cwd: str = ".",
        timeout: int = 120,
    ) -> CommandResult:
        self.state.calls.append(("run_command", name, command, cwd, timeout))
        return self.state.submissions[name]

    def run_approved(
        self,
        request_id: str,
        *,
        name: str,
        resume_tool: str | None = None,
    ) -> CommandResult:
        self.state.calls.append(("run_approved", request_id))
        assert resume_tool == "shell.run_approved"
        return self.state.approved_commands[request_id]

    def git_diff(self, path: str | None = None, staged: bool = False) -> GitDiffResult:
        self.state.calls.append(("git_diff", path, staged))
        return self.state.diff


def pending_command(name: str, command: tuple[str, ...], request_id: str) -> CommandResult:
    return CommandResult(
        name,
        command,
        126,
        "",
        "",
        0.1,
        approval_required=True,
        request_id=request_id,
        approval_status="PENDING",
        message="Approval required.",
        executed=False,
        trace_id=f"trc_{request_id}",
        toolhub_outcome="APPROVAL_REQUIRED",
        resume_tool="shell.run_approved",
        expires_at=EXPIRES_AT,
    )


def approved_command(
    name: str,
    command: tuple[str, ...],
    request_id: str,
    *,
    exit_code: int = 0,
) -> CommandResult:
    return CommandResult(
        name,
        command,
        exit_code,
        "1 passed\n" if exit_code == 0 else "1 failed\n",
        "",
        0.2,
        request_id=request_id,
        approval_status="CONSUMED",
        executed=True,
        trace_id=f"trc_{request_id}",
        toolhub_outcome="SUCCEEDED" if exit_code == 0 else "COMMAND_FAILED",
        resume_tool="shell.run_approved",
        expires_at=EXPIRES_AT,
    )


def refused_command(
    name: str,
    command: tuple[str, ...],
    request_id: str,
    status: str,
) -> CommandResult:
    outcome = {
        "PENDING": "APPROVAL_PENDING",
        "APPROVED": "APPROVAL_APPROVED",
        "REJECTED": "APPROVAL_REJECTED",
        "EXPIRED": "APPROVAL_EXPIRED",
        "CONSUMED": "APPROVAL_CONSUMED",
    }[status]
    return CommandResult(
        name,
        command,
        126,
        "",
        "",
        0.1,
        approval_required=status == "PENDING",
        request_id=request_id,
        approval_status=status,
        message=f"Request is {status}.",
        executed=False,
        trace_id=f"trc_{request_id}",
        toolhub_outcome=outcome,
        resume_tool="shell.run_approved",
        expires_at=EXPIRES_AT,
    )


@pytest.fixture
def state_root(tmp_path: Path, monkeypatch) -> Path:
    root = tmp_path / "state"
    monkeypatch.setenv("REPO_DOCTOR_STATE_ROOT", str(root))
    return root


def repair_repository(root: Path) -> bytes:
    (root / "pyproject.toml").write_text(
        "[project]\nname='fixture'\nversion='1.0'\n[tool.pytest.ini_options]\npythonpath=['.']\n",
        encoding="utf-8",
    )
    target = root / "inventory.py"
    target.write_text(
        "def can_fulfill(stock, requested):\n    return requested < stock\n",
        encoding="utf-8",
    )
    tests = root / "tests"
    tests.mkdir()
    (tests / "test_inventory.py").write_text(
        "from inventory import can_fulfill\n\n\ndef test_exact():\n    assert can_fulfill(2, 2)\n",
        encoding="utf-8",
    )
    return target.read_bytes()


def backend_factory(state: SharedBackendState):
    return lambda root: FakeRepairBackend(root, state)


def pending_repair(root: Path) -> object:
    session = new_repair_session(
        root,
        finding_id="boundary-1",
        finding_title="Exact stock is rejected",
        target_file="inventory.py",
        expected_hash="1" * 64,
        proposed_hash="2" * 64,
        verification_plan=(
            VerificationPlan("Python tests", ("pytest",)),
            VerificationPlan("Python lint", ("ruff", "check", ".")),
        ),
    )
    record_patch_request(
        session,
        PatchMutationResult(
            path="inventory.py",
            executed=False,
            trace_id="trc_patch_request",
            request_id="req_patch",
            approval_status="PENDING",
            toolhub_outcome="APPROVAL_REQUIRED",
            resume_tool="filesystem.apply_patch_approved",
            expires_at=EXPIRES_AT,
        ),
    )
    save_repair_session(session)
    return session


def test_mcp_backend_patch_calls_use_exact_immutable_tool_shapes(tmp_path: Path) -> None:
    expected_hash = hashlib.sha256(b"old\n").hexdigest()
    patch_response = {
        "outcome": "APPROVAL_REQUIRED",
        "trace_id": "trc_patch",
        "approval": {
            "request_id": "req_patch",
            "status": "PENDING",
            "expires_at": EXPIRES_AT,
            "resume_tool": "filesystem.apply_patch_approved",
        },
        "error": None,
        "path": "app.py",
        "executed": False,
        "request_id": "req_patch",
        "approval_status": "PENDING",
        "message": "Approval required.",
    }
    approved_response = {
        "outcome": "SUCCEEDED",
        "trace_id": "trc_patch",
        "approval": {
            "request_id": "req_patch",
            "status": "CONSUMED",
            "expires_at": EXPIRES_AT,
            "resume_tool": "filesystem.apply_patch_approved",
        },
        "error": None,
        "path": "app.py",
        "executed": True,
        "changed": True,
        "additions": 1,
        "deletions": 1,
        "bytes_before": 4,
        "bytes_after": 4,
        "previous_hash": expected_hash,
        "new_hash": hashlib.sha256(b"new\n").hexdigest(),
        "request_id": "req_patch",
        "approval_status": "CONSUMED",
    }

    class Client:
        def __init__(self):
            self.calls = []

        def start(self):
            return None

        def close(self):
            return None

        def call_tool(self, name, arguments):
            self.calls.append((name, arguments))
            if name == "toolhub.capabilities":
                return capabilities_response()
            return patch_response if name == "filesystem.apply_patch" else approved_response

    client = Client()
    project = prepare_toolhub_project(tmp_path / "toolhub")
    backend = MCPToolBackend(
        tmp_path,
        toolhub_project=project,
        client_factory=lambda _process: client,
    )
    patch = "--- a/app.py\n+++ b/app.py\n@@ -1 +1 @@\n-old\n+new\n"

    with backend:
        pending = backend.apply_patch("app.py", patch, expected_hash)
        applied = backend.run_approved_mutation(
            "req_patch",
            expected_path="app.py",
            expected_trace_id="trc_patch",
        )

    assert pending.approval_required
    assert pending.trace_id == "trc_patch"
    assert applied.executed and applied.approval_status == "CONSUMED"
    assert client.calls == [
        ("toolhub.capabilities", {}),
        (
            "filesystem.apply_patch",
            {"path": "app.py", "patch": patch, "expected_hash": expected_hash},
        ),
        ("filesystem.apply_patch_approved", {"request_id": "req_patch"}),
    ]


def test_mcp_backend_maps_stale_hash_to_repair_conflict(tmp_path: Path) -> None:
    class Client:
        def start(self):
            return None

        def close(self):
            return None

        def call_tool(self, name, arguments):
            if name == "toolhub.capabilities":
                return capabilities_response()
            return {
                "outcome": "CONFLICT",
                "trace_id": "trc_conflict",
                "approval": None,
                "error": {
                    "code": "EXPECTED_HASH_MISMATCH",
                    "message": "app.py hash is stale",
                    "retryable": False,
                },
                "path": "app.py",
                "executed": False,
                "changed": False,
            }

    project = prepare_toolhub_project(tmp_path / "toolhub")
    backend = MCPToolBackend(
        tmp_path,
        toolhub_project=project,
        client_factory=lambda _process: Client(),
    )
    with backend, pytest.raises(MutationConflictError, match="hash is stale"):
        backend.apply_patch("app.py", "patch", "1" * 64)


def approved_conflict_response() -> dict:
    return {
        "outcome": "CONFLICT",
        "trace_id": "trc_patch",
        "approval": {
            "request_id": "req_patch",
            "status": "CONSUMED",
            "expires_at": EXPIRES_AT,
            "resume_tool": "filesystem.apply_patch_approved",
        },
        "error": {
            "code": "MUTATION_CONFLICT",
            "message": "target changed after approval",
            "retryable": False,
        },
        "path": "app.py",
        "executed": False,
        "changed": False,
        "request_id": "req_patch",
        "approval_status": "CONSUMED",
    }


@pytest.mark.parametrize(
    "contradiction",
    [
        "executed",
        "changed",
        "path",
        "request_id",
        "trace_id",
        "approval_status",
        "approval_request_id",
    ],
)
def test_mcp_backend_rejects_contradictory_conflict_before_classification(
    tmp_path: Path, contradiction: str
) -> None:
    payload = approved_conflict_response()
    if contradiction in {"executed", "changed"}:
        payload[contradiction] = True
    elif contradiction == "path":
        payload["path"] = "other.py"
    elif contradiction == "request_id":
        payload["request_id"] = "req_other"
    elif contradiction == "trace_id":
        payload["trace_id"] = "trc_other"
    elif contradiction == "approval_status":
        payload["approval_status"] = "APPROVED"
    else:
        payload["approval"]["request_id"] = "req_other"
        payload["request_id"] = "req_other"

    class Client:
        def start(self):
            return None

        def close(self):
            return None

        def call_tool(self, name, arguments):
            if name == "toolhub.capabilities":
                return capabilities_response()
            return payload

    project = prepare_toolhub_project(tmp_path / "toolhub")
    backend = MCPToolBackend(
        tmp_path,
        toolhub_project=project,
        client_factory=lambda _process: Client(),
    )

    with backend, pytest.raises(ToolCallError, match="invalid filesystem patch result"):
        backend.run_approved_mutation(
            "req_patch",
            expected_path="app.py",
            expected_trace_id="trc_patch",
        )


def test_mcp_backend_classifies_only_coherent_structured_conflict(tmp_path: Path) -> None:
    payload = approved_conflict_response()

    class Client:
        def start(self):
            return None

        def close(self):
            return None

        def call_tool(self, name, arguments):
            if name == "toolhub.capabilities":
                return capabilities_response()
            return payload

    project = prepare_toolhub_project(tmp_path / "toolhub")
    backend = MCPToolBackend(
        tmp_path,
        toolhub_project=project,
        client_factory=lambda _process: Client(),
    )

    with backend, pytest.raises(MutationConflictError) as captured:
        backend.run_approved_mutation(
            "req_patch",
            expected_path="app.py",
            expected_trace_id="trc_patch",
        )

    assert captured.value.trace_id == "trc_patch"
    assert captured.value.error_code == "MUTATION_CONFLICT"


def test_mcp_patch_validation_accepts_toolhub_normalized_windows_newlines(
    tmp_path: Path,
) -> None:
    proposal = PatchProposal("app.py", "old", "new", "repair", 0.95)
    raw_hash = hashlib.sha256(b"old\r\n").hexdigest()

    prepared = prepare_patch_from_content(
        tmp_path,
        proposal,
        content="old\n",
        expected_sha256=raw_hash,
    )

    assert prepared.updated_bytes == b"new\n"


def test_mcp_ai_repair_uses_read_hash_and_never_writes_locally(
    tmp_path: Path, state_root: Path, monkeypatch
) -> None:
    original = repair_repository(tmp_path)
    state = SharedBackendState()
    monkeypatch.setattr(
        "repo_doctor.ai.patching._atomic_write",
        lambda *args: pytest.fail("MCP repair reached the local write path"),
    )
    monkeypatch.setattr(
        "repo_doctor.ai.patching.rollback_patch",
        lambda *args: pytest.fail("MCP repair reached the local rollback path"),
    )
    monkeypatch.setattr(
        "repo_doctor.fixer.subprocess.run",
        lambda *args, **kwargs: pytest.fail("MCP repair used a local Git subprocess"),
    )

    outcome = execute_mcp_ai_fix(
        tmp_path,
        DeterministicRepairProvider(),
        trusted_execution=True,
        backend_factory=backend_factory(state),
    )

    assert outcome.status == RepairPhase.PATCH_PENDING.value
    assert (tmp_path / "inventory.py").read_bytes() == original
    read_call = next(call for call in state.calls if call[:2] == ("read_file", "inventory.py"))
    apply_call = next(call for call in state.calls if call[0] == "apply_patch")
    assert read_call
    assert apply_call[3] == hashlib.sha256(original).hexdigest()
    assert apply_call[1] == "inventory.py"
    assert "requested <= stock" in apply_call[2]
    assert not any(call[0] == "run_command" for call in state.calls)
    stored = session_file_path(outcome.session.session_id).read_text(encoding="utf-8")
    assert "return requested <= stock" not in stored
    assert '"approved"' not in stored.casefold()
    assert '"expected_hash"' in stored


def test_mcp_ai_repair_plumbs_task_and_contract_without_changing_session_flow(
    tmp_path: Path, state_root: Path
) -> None:
    repair_repository(tmp_path)
    state = SharedBackendState()
    provider = DeterministicRepairProvider()

    outcome = execute_mcp_ai_fix(
        tmp_path,
        provider,
        trusted_execution=True,
        task="Accept exact stock while preserving existing behavior.",
        backend_factory=backend_factory(state),
    )

    assert outcome.status == RepairPhase.PATCH_PENDING.value
    assert provider.analysis_request.task == (
        "Accept exact stock while preserving existing behavior."
    )
    contract = provider.patch_request.behavioral_contract
    assert any("Satisfy the user task" in item for item in contract.must_fix)
    assert any("boundary-1" in item for item in contract.must_fix)
    assert outcome.session.pending_operations


def test_mcp_static_baseline_does_not_claim_discovered_commands_are_missing(
    tmp_path: Path,
) -> None:
    repair_repository(tmp_path)
    state = SharedBackendState()
    provider = DeterministicRepairProvider()

    outcome = execute_mcp_ai_fix(
        tmp_path,
        provider,
        backend_factory=backend_factory(state),
    )

    assert outcome.status == "preview"
    assert provider.analysis_request.verifications == ()
    assert not any(
        "No supported test or lint commands" in item
        for item in provider.analysis_request.deterministic_findings
    )
    assert not any(call[0] in {"run_command", "apply_patch"} for call in state.calls)


def test_malformed_ai_patch_is_rejected_before_toolhub_mutation(
    tmp_path: Path, state_root: Path
) -> None:
    repair_repository(tmp_path)
    state = SharedBackendState()

    with pytest.raises(PatchValidationError, match="was not found"):
        execute_mcp_ai_fix(
            tmp_path,
            DeterministicRepairProvider(old_text="not present"),
            backend_factory=backend_factory(state),
        )

    assert not any(call[0] == "apply_patch" for call in state.calls)
    assert not list((state_root / "sessions").glob("*.json"))


def test_stale_hash_conflict_persists_distinct_state_and_leaves_file_unchanged(
    tmp_path: Path, state_root: Path
) -> None:
    original = repair_repository(tmp_path)
    state = SharedBackendState()
    state.patch_error = MutationConflictError("Conflict: expected hash is stale")

    outcome = execute_mcp_ai_fix(
        tmp_path,
        DeterministicRepairProvider(),
        trusted_execution=True,
        backend_factory=backend_factory(state),
    )

    assert outcome.session.phase is RepairPhase.PATCH_CONFLICT
    assert outcome.session.patch_operation.status is RepairOperationStatus.CONFLICT
    assert (tmp_path / "inventory.py").read_bytes() == original
    loaded = load_repair_session(outcome.session.session_id)
    assert loaded.phase is RepairPhase.PATCH_CONFLICT


@pytest.mark.parametrize(
    ("toolhub_status", "expected_phase", "expected_status"),
    [
        ("PENDING", RepairPhase.PATCH_PENDING, RepairOperationStatus.PENDING),
        ("REJECTED", RepairPhase.PATCH_REJECTED, RepairOperationStatus.REJECTED),
        ("EXPIRED", RepairPhase.PATCH_EXPIRED, RepairOperationStatus.EXPIRED),
        ("CONSUMED", RepairPhase.ERROR, RepairOperationStatus.CONSUMED),
    ],
)
def test_patch_resume_maps_authoritative_toolhub_states(
    tmp_path: Path,
    state_root: Path,
    toolhub_status: str,
    expected_phase: RepairPhase,
    expected_status: RepairOperationStatus,
) -> None:
    session = pending_repair(tmp_path)
    state = SharedBackendState()
    outcome = {
        "PENDING": "APPROVAL_PENDING",
        "REJECTED": "APPROVAL_REJECTED",
        "EXPIRED": "APPROVAL_EXPIRED",
        "CONSUMED": "APPROVAL_CONSUMED",
    }[toolhub_status]
    state.approved_patch_result = PatchMutationResult(
        path="inventory.py",
        executed=False,
        trace_id="trc_patch_request",
        request_id="req_patch",
        approval_status=toolhub_status,
        message=f"Request is {toolhub_status}.",
        toolhub_outcome=outcome,
        resume_tool="filesystem.apply_patch_approved",
        expires_at=EXPIRES_AT,
    )

    resume_repair_session(session, backend_factory=backend_factory(state))

    assert session.phase is expected_phase
    assert session.patch_operation.status is expected_status
    assert [call for call in state.calls if call[0] == "run_approved_mutation"] == []
    assert load_repair_session(session.session_id).phase is expected_phase


def test_patch_and_verification_share_session_and_make_partial_progress(
    tmp_path: Path, state_root: Path
) -> None:
    session = pending_repair(tmp_path)
    state = SharedBackendState()

    resume_repair_session(session, backend_factory=backend_factory(state))

    assert session.phase is RepairPhase.VERIFICATION_PENDING
    assert [item.kind for item in session.operations] == [
        RepairOperationKind.PATCH,
        RepairOperationKind.VERIFICATION,
        RepairOperationKind.VERIFICATION,
    ]
    assert session.patch_operation.status is RepairOperationStatus.COMPLETED
    assert session.patch_operation.toolhub_status == "CONSUMED"
    assert session.patch_trace_id == "trc_patch_request"
    assert session.diff_summary.additions == 1
    assert ("git_diff", "inventory.py", False) in state.calls

    state.approved_commands = {
        "req_tests": approved_command("Python tests", ("pytest",), "req_tests"),
        "req_lint": pending_command("Python lint", ("ruff", "check", "."), "req_lint"),
    }
    resume_repair_session(session, backend_factory=backend_factory(state))
    assert session.phase is RepairPhase.VERIFICATION_PENDING
    statuses = {item.request_id: item.status for item in session.operations[1:]}
    assert statuses == {
        "req_tests": RepairOperationStatus.COMPLETED,
        "req_lint": RepairOperationStatus.PENDING,
    }

    state.approved_commands["req_lint"] = approved_command(
        "Python lint", ("ruff", "check", "."), "req_lint"
    )
    resume_repair_session(session, backend_factory=backend_factory(state))
    assert session.phase is RepairPhase.VERIFIED_PASS
    loaded = load_repair_session(session.session_id)
    assert loaded.phase is RepairPhase.VERIFIED_PASS
    assert {item.trace_id for item in loaded.operations if item.trace_id} == {
        "trc_patch_request",
        "trc_req_tests",
        "trc_req_lint",
    }
    persisted = session_file_path(session.session_id).read_text(encoding="utf-8")
    assert "return requested <= stock" not in persisted

    resume_repair_session(
        session,
        backend_factory=lambda _root: pytest.fail("completed repair must not reopen ToolHub"),
    )
    assert [call for call in state.calls if call[0] == "run_approved_mutation"] == [
        ("run_approved_mutation", "req_patch")
    ]


@pytest.mark.parametrize(
    ("toolhub_status", "expected_phase"),
    [
        ("REJECTED", RepairPhase.VERIFICATION_REJECTED),
        ("EXPIRED", RepairPhase.VERIFICATION_EXPIRED),
    ],
)
def test_verification_refusal_is_distinct_from_test_failure(
    tmp_path: Path,
    state_root: Path,
    toolhub_status: str,
    expected_phase: RepairPhase,
) -> None:
    session = pending_repair(tmp_path)
    state = SharedBackendState()
    resume_repair_session(session, backend_factory=backend_factory(state))
    state.approved_commands = {
        "req_tests": refused_command("Python tests", ("pytest",), "req_tests", toolhub_status),
        "req_lint": approved_command("Python lint", ("ruff", "check", "."), "req_lint"),
    }

    resume_repair_session(session, backend_factory=backend_factory(state))

    assert session.phase is expected_phase
    refused = next(item for item in session.operations if item.request_id == "req_tests")
    assert refused.status.value == toolhub_status.casefold()
    assert refused.exit_code is None
    assert all(item.status is not RepairOperationStatus.FAILED for item in session.operations)


def test_approved_without_execution_becomes_unknown_without_local_authorization(
    tmp_path: Path, state_root: Path
) -> None:
    session = pending_repair(tmp_path)
    state = SharedBackendState()
    resume_repair_session(session, backend_factory=backend_factory(state))
    state.approved_commands = {
        "req_tests": refused_command("Python tests", ("pytest",), "req_tests", "APPROVED"),
        "req_lint": approved_command("Python lint", ("ruff", "check", "."), "req_lint"),
    }

    resume_repair_session(session, backend_factory=backend_factory(state))

    assert session.phase is RepairPhase.ERROR
    assert "APPROVAL_APPROVED without executing" in session.error
    unknown = next(item for item in session.operations if item.request_id == "req_tests")
    assert unknown.status is RepairOperationStatus.UNKNOWN
    assert unknown.toolhub_status == "APPROVED"
    stored = session_file_path(session.session_id).read_text(encoding="utf-8")
    assert '"approved": true' not in stored.casefold()


def test_conflict_during_approved_patch_resume_is_persisted(
    tmp_path: Path, state_root: Path
) -> None:
    session = pending_repair(tmp_path)
    state = SharedBackendState()

    class ConflictBackend(FakeRepairBackend):
        def run_approved_mutation(
            self,
            request_id: str,
            *,
            resume_tool: str | None = None,
            expected_path: str,
            expected_trace_id: str,
        ) -> PatchMutationResult:
            self.state.calls.append(("run_approved_mutation", request_id))
            assert resume_tool == "filesystem.apply_patch_approved"
            assert expected_path == "inventory.py"
            assert expected_trace_id == "trc_patch_request"
            raise MutationConflictError(
                "target changed after approval",
                trace_id="trc_patch_request",
                error_code="EXPECTED_HASH_MISMATCH",
            )

    resume_repair_session(
        session,
        backend_factory=lambda root: ConflictBackend(root, state),
    )

    assert session.phase is RepairPhase.PATCH_CONFLICT
    assert session.patch_operation.status is RepairOperationStatus.CONFLICT
    assert load_repair_session(session.session_id).phase is RepairPhase.PATCH_CONFLICT


def test_resume_binds_only_the_stored_canonical_workspace(
    tmp_path: Path, state_root: Path, monkeypatch
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    session = pending_repair(target)
    state = SharedBackendState()
    monkeypatch.chdir(other)

    resume_repair_session(session, backend_factory=backend_factory(state))

    assert state.roots
    assert set(state.roots) == {target.resolve()}


def test_repair_phase_persistence_uses_atomic_replace(
    tmp_path: Path, state_root: Path, monkeypatch
) -> None:
    session = new_repair_session(
        tmp_path,
        finding_id="boundary-1",
        finding_title="Exact stock is rejected",
        target_file="inventory.py",
        expected_hash="1" * 64,
        proposed_hash="2" * 64,
        verification_plan=(VerificationPlan("Python tests", ("pytest",)),),
    )
    record_patch_request(
        session,
        PatchMutationResult(
            path="inventory.py",
            executed=False,
            trace_id="trc_patch_request",
            request_id="req_patch",
            approval_status="PENDING",
            toolhub_outcome="APPROVAL_REQUIRED",
            resume_tool="filesystem.apply_patch_approved",
            expires_at=EXPIRES_AT,
        ),
    )
    replacements = []
    real_replace = os.replace

    def recording_replace(source, destination):
        replacements.append((Path(source), Path(destination)))
        real_replace(source, destination)

    monkeypatch.setattr("repo_doctor.repair_sessions.os.replace", recording_replace)
    destination = save_repair_session(session)

    assert len(replacements) == 1
    assert replacements[0][1] == destination
    assert replacements[0][0].suffix == ".tmp"
    assert not replacements[0][0].exists()
    assert load_repair_session(session.session_id).phase is RepairPhase.PATCH_PENDING


def oversized_verification_plan() -> tuple[VerificationPlan, ...]:
    return (VerificationPlan("Oversized command", tuple("x" * 20_000 for _ in range(60))),)


def test_oversized_repair_update_preserves_previous_file_and_leaves_no_temp(
    tmp_path: Path, state_root: Path
) -> None:
    session = new_repair_session(
        tmp_path,
        finding_id="boundary-1",
        finding_title="Exact stock is rejected",
        target_file="inventory.py",
        expected_hash="1" * 64,
        proposed_hash="2" * 64,
        verification_plan=(VerificationPlan("Python tests", ("pytest",)),),
    )
    destination = save_repair_session(session)
    original = destination.read_bytes()
    session.verification_plan = oversized_verification_plan()

    with pytest.raises(SessionError, match="exceeds.*safety limit"):
        save_repair_session(session)

    assert destination.read_bytes() == original
    assert not list(destination.parent.glob(f".{session.session_id}.*.tmp"))


def test_oversized_first_repair_save_leaves_no_file_or_temp(
    tmp_path: Path, state_root: Path
) -> None:
    session = new_repair_session(
        tmp_path,
        finding_id="boundary-1",
        finding_title="Exact stock is rejected",
        target_file="inventory.py",
        expected_hash="1" * 64,
        proposed_hash="2" * 64,
        verification_plan=oversized_verification_plan(),
    )
    destination = session_file_path(session.session_id)

    with pytest.raises(SessionError, match="exceeds.*safety limit"):
        save_repair_session(session)

    assert not destination.exists()
    assert not destination.parent.exists() or not list(
        destination.parent.glob(f".{session.session_id}.*.tmp")
    )


def test_resume_cli_prints_patch_approval_guidance(
    tmp_path: Path, state_root: Path, monkeypatch
) -> None:
    session = pending_repair(tmp_path)
    monkeypatch.setattr("repo_doctor.cli.resume_repair_session", lambda value: value)

    response = CliRunner().invoke(app, ["resume", session.session_id])

    assert response.exit_code == 0, response.output
    assert "Patch approval required" in response.output
    assert session.session_id in response.output
    assert "boundary-1" in response.output
    assert "inventory.py" in response.output
    assert "req_patch" in response.output
    assert "mcp-toolhub-admin approve" in response.output


def test_actual_verification_failure_is_not_approval_failure(
    tmp_path: Path, state_root: Path
) -> None:
    session = pending_repair(tmp_path)
    state = SharedBackendState()
    state.submissions = {
        "Python tests": approved_command("Python tests", ("pytest",), "req_low_tests", exit_code=1),
        "Python lint": approved_command("Python lint", ("ruff", "check", "."), "req_low_lint"),
    }

    resume_repair_session(session, backend_factory=backend_factory(state))

    assert session.phase is RepairPhase.VERIFICATION_FAILED
    failed = next(
        item for item in session.operations if item.status is RepairOperationStatus.FAILED
    )
    assert failed.exit_code == 1
    assert failed.toolhub_status == "CONSUMED"
    assert session.diff_summary is not None


def test_repair_session_rejects_substituted_patch_target(tmp_path: Path, state_root: Path) -> None:
    session = pending_repair(tmp_path)
    path = session_file_path(session.session_id)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["operations"][0]["target_file"] = "other.py"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(SessionError, match="does not match the repair target"):
        load_repair_session(session.session_id)


def test_repair_trace_mismatch_fails_before_patch_resume(tmp_path: Path, state_root: Path) -> None:
    session = pending_repair(tmp_path)
    state = SharedBackendState()

    class TraceMismatchBackend(FakeRepairBackend):
        def request_status(self, request_id: str) -> RequestStatusResult:
            status = super().request_status(request_id)
            return RequestStatusResult(
                status.request_id,
                status.outcome,
                "trc_different",
                status.approval,
                status.error,
            )

    with pytest.raises(SessionError, match="trace_id changed"):
        resume_repair_session(
            session,
            backend_factory=lambda root: TraceMismatchBackend(root, state),
        )

    assert not any(call[0] == "run_approved_mutation" for call in state.calls)


def test_repair_session_rejects_arbitrary_resume_tool(tmp_path: Path, state_root: Path) -> None:
    session = pending_repair(tmp_path)
    path = session_file_path(session.session_id)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["operations"][0]["resume_tool"] = "attacker.execute"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(SessionError, match="unsafe resume_tool"):
        load_repair_session(session.session_id)


def test_schema_v1_repair_approval_migrates_to_non_resumable_state(
    tmp_path: Path, state_root: Path
) -> None:
    session = pending_repair(tmp_path)
    path = session_file_path(session.session_id)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["schema_version"] = 1
    for operation in payload["operations"]:
        for field in (
            "toolhub_outcome",
            "resume_tool",
            "expires_at",
            "error_code",
            "error_retryable",
        ):
            operation.pop(field)
    path.write_text(json.dumps(payload), encoding="utf-8")

    migrated = load_repair_session(session.session_id)

    assert migrated.schema_version == 2
    assert migrated.phase is RepairPhase.ERROR
    assert migrated.patch_operation is not None
    assert migrated.patch_operation.status is RepairOperationStatus.UNKNOWN
    assert not migrated.pending_operations
    assert migrated.patch_operation.resume_tool is None
    assert migrated.patch_operation.toolhub_outcome is None
    assert migrated.patch_operation.toolhub_status != "APPROVED"


def test_terminal_schema_v1_repair_session_remains_readable(
    tmp_path: Path, state_root: Path
) -> None:
    session = pending_repair(tmp_path)
    path = session_file_path(session.session_id)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["schema_version"] = 1
    payload["phase"] = "patch_rejected"
    payload["error"] = "Rejected by operator."
    operation = payload["operations"][0]
    operation["status"] = "rejected"
    operation["toolhub_status"] = "REJECTED"
    for field in (
        "toolhub_outcome",
        "resume_tool",
        "expires_at",
        "error_code",
        "error_retryable",
    ):
        operation.pop(field)
    path.write_text(json.dumps(payload), encoding="utf-8")

    migrated = load_repair_session(session.session_id)

    assert migrated.schema_version == 2
    assert migrated.phase is RepairPhase.PATCH_REJECTED
    assert migrated.patch_operation is not None
    assert migrated.patch_operation.status is RepairOperationStatus.REJECTED
    assert migrated.patch_operation.toolhub_status == "REJECTED"
    assert migrated.patch_operation.resume_tool is None
    assert migrated.patch_operation.toolhub_outcome is None
    assert not migrated.pending_operations


def test_future_repair_session_schema_fails_closed(tmp_path: Path, state_root: Path) -> None:
    session = pending_repair(tmp_path)
    path = session_file_path(session.session_id)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["schema_version"] = 999
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(SessionError, match="Unsupported repair session schema version 999"):
        load_repair_session(session.session_id)


def test_local_ai_fix_remains_the_default_cli_path(tmp_path: Path, monkeypatch) -> None:
    observed = {}
    monkeypatch.setattr("repo_doctor.cli.provider_from_env", lambda **kwargs: object())

    def local_fix(root, provider, **kwargs):
        observed.update(root=root, provider=provider, kwargs=kwargs)
        return SimpleNamespace(status="no_candidate")

    monkeypatch.setattr("repo_doctor.cli.execute_ai_fix", local_fix)
    monkeypatch.setattr(
        "repo_doctor.cli.execute_mcp_ai_fix",
        lambda *args, **kwargs: pytest.fail("default local fix selected MCP"),
    )

    response = CliRunner().invoke(app, ["fix", str(tmp_path), "--ai"])

    assert response.exit_code == 0, response.output
    assert observed["root"] == tmp_path.resolve()
    assert observed["kwargs"]["trusted_execution"] is False
    assert ToolBackendKind.LOCAL.value not in response.output


def test_mcp_fix_cli_passes_task_but_rejects_local_report_json(tmp_path: Path, monkeypatch) -> None:
    observed = {}
    monkeypatch.setattr("repo_doctor.cli.provider_from_env", lambda **kwargs: object())

    def mcp_fix(root, provider, **kwargs):
        observed.update(root=root, provider=provider, kwargs=kwargs)
        return SimpleNamespace(status="no_candidate", session=None, diff="")

    monkeypatch.setattr("repo_doctor.cli.execute_mcp_ai_fix", mcp_fix)
    task_response = CliRunner().invoke(
        app,
        [
            "fix",
            str(tmp_path),
            "--ai",
            "--tool-backend",
            "mcp",
            "--task",
            "Preserve the public API.",
        ],
    )

    assert task_response.exit_code == 0, task_response.output
    assert observed["kwargs"]["task"] == "Preserve the public API."
    assert observed["kwargs"]["trusted_execution"] is False

    def forbidden(*_args, **_kwargs):
        raise AssertionError("provider and MCP workflow must not be called")

    monkeypatch.setattr("repo_doctor.cli.provider_from_env", forbidden)
    monkeypatch.setattr("repo_doctor.cli.execute_mcp_ai_fix", forbidden)
    report_response = CliRunner().invoke(
        app,
        [
            "fix",
            str(tmp_path),
            "--ai",
            "--tool-backend",
            "mcp",
            "--report-json",
            str(tmp_path / "report.json"),
        ],
    )

    assert report_response.exit_code == 2
    assert "available only with --tool-backend local" in report_response.output


@pytest.mark.integration
def test_real_toolhub_ai_repair_approval_verification_diff_and_audit(
    tmp_path: Path,
    monkeypatch,
) -> None:
    if os.environ.get("REPO_DOCTOR_RUN_TOOLHUB_INTEGRATION") != "1":
        pytest.skip("set REPO_DOCTOR_RUN_TOOLHUB_INTEGRATION=1 to run real ToolHub integration")
    toolhub = Path(r"D:\mcp-toolhub")
    production_python = toolhub / ".venv" / "Scripts" / "python.exe"
    admin = toolhub / ".venv" / "Scripts" / "mcp-toolhub-admin.exe"
    if not all(path.is_file() for path in (production_python, admin)):
        pytest.skip(r"real ToolHub is unavailable at D:\mcp-toolhub")

    repository = tmp_path / "repository"
    repository.mkdir()
    repair_repository(repository)
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

    state = tmp_path / "toolhub-state"
    toolhub_state = state / "toolhub"
    monkeypatch.setenv("REPO_DOCTOR_TOOLHUB_PROJECT", str(toolhub.resolve()))
    monkeypatch.setenv("TOOLHUB_STATE_ROOT", str(toolhub_state))
    monkeypatch.setenv("REPO_DOCTOR_STATE_ROOT", str(state / "repo-doctor-state"))

    outcome = execute_mcp_ai_fix(
        repository,
        DeterministicRepairProvider(),
        trusted_execution=True,
    )
    assert outcome.session is not None
    session = outcome.session
    assert session.phase is RepairPhase.PATCH_PENDING
    patch_request = session.patch_operation.request_id

    def approve(request_id: str) -> None:
        environment = os.environ.copy()
        environment["TOOLHUB_WORKSPACE_ROOT"] = str(repository.resolve())
        subprocess.run(
            [str(admin), "approve", request_id],
            cwd=toolhub,
            env=environment,
            input="APPROVE\n",
            capture_output=True,
            text=True,
            check=True,
        )

    approve(patch_request)
    resume_repair_session(session)
    assert session.phase is RepairPhase.VERIFICATION_PENDING
    verification_requests = [
        item.request_id
        for item in session.pending_operations
        if item.kind is RepairOperationKind.VERIFICATION
    ]
    assert len(verification_requests) == 2
    for request_id in verification_requests:
        approve(request_id)

    resume_repair_session(session)
    assert session.phase is RepairPhase.VERIFIED_PASS
    assert "requested <= stock" in (repository / "inventory.py").read_text(encoding="utf-8")
    assert session.diff_summary is not None
    with MCPToolBackend(repository, toolhub_project=toolhub) as backend:
        actual_diff = backend.git_diff("inventory.py")
    assert "requested <= stock" in actual_diff.raw
    persisted = session_file_path(session.session_id).read_text(encoding="utf-8")
    assert "return requested <= stock" not in persisted

    with MCPToolBackend(repository, toolhub_project=toolhub) as backend:
        for request_id in (patch_request, *verification_requests):
            assert backend.request_status(request_id).outcome is ContractOutcome.APPROVAL_CONSUMED

    resume_repair_session(
        session,
        backend_factory=lambda _root: pytest.fail("completed repair reopened ToolHub"),
    )
    assert not any(thread.name == "repo-doctor-mcp" for thread in threading.enumerate())
