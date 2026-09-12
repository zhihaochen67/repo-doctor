import json
import subprocess
from pathlib import Path

import pytest
from typer.testing import CliRunner

from repo_doctor.cli import app
from repo_doctor.models import CommandResult, ScanResult
from repo_doctor.report import render_report
from repo_doctor.sessions import (
    OperationStatus,
    SessionError,
    SessionStatus,
    create_scan_session,
    default_state_root,
    load_session,
    load_session_file,
    resume_scan_session,
    save_session,
    session_file_path,
    state_root,
)
from repo_doctor.toolhub_contract import (
    ApprovalHandle,
    ApprovalStatus,
    ContractError,
    ContractOutcome,
    RequestStatusResult,
)

EXPIRES_AT = "2099-01-01T00:00:00Z"


@pytest.fixture
def state_root_dir(tmp_path: Path, monkeypatch) -> Path:
    root = tmp_path / "repo-doctor-state"
    monkeypatch.setenv("REPO_DOCTOR_STATE_ROOT", str(root))
    return root


def command_result(
    name: str,
    command: tuple[str, ...],
    request_id: str,
    *,
    status: str = "PENDING",
    executed: bool = False,
    exit_code: int | None = None,
    stdout: str = "",
) -> CommandResult:
    if executed:
        outcome = "SUCCEEDED" if (exit_code in {None, 0}) else "COMMAND_FAILED"
    else:
        outcome = {
            "PENDING": "APPROVAL_REQUIRED",
            "REJECTED": "APPROVAL_REJECTED",
            "EXPIRED": "APPROVAL_EXPIRED",
            "CONSUMED": "APPROVAL_CONSUMED",
        }.get(status, "REFUSED")
    return CommandResult(
        name=name,
        command=command,
        exit_code=(0 if executed else 126) if exit_code is None else exit_code,
        stdout=stdout,
        stderr="",
        duration=0.1,
        approval_required=not executed and status == "PENDING",
        request_id=request_id,
        approval_status=status,
        message=f"Request is {status}.",
        executed=executed,
        trace_id=f"trc_{request_id}",
        toolhub_outcome=outcome,
        resume_tool=(
            "shell.run_approved"
            if status in {"PENDING", "REJECTED", "EXPIRED", "CONSUMED"}
            else None
        ),
        expires_at=(
            EXPIRES_AT if status in {"PENDING", "REJECTED", "EXPIRED", "CONSUMED"} else None
        ),
    )


def scan_result(root: Path, *commands: CommandResult) -> ScanResult:
    return ScanResult(
        path=root,
        technologies=["Python"],
        files=2,
        lines=4,
        inspected_files=["pyproject.toml"],
        commands=list(commands),
    )


def pending_session(root: Path, *, two: bool = False):
    commands = [command_result("Python tests", ("pytest",), "req_tests")]
    if two:
        commands.append(command_result("Python lint", ("ruff", "check", "."), "req_lint"))
    session = create_scan_session(scan_result(root, *commands))
    save_session(session)
    return session


class FakeApprovedBackend:
    def __init__(self, root: Path, responses: dict[str, CommandResult], calls: list[str]):
        self.root = root
        self.responses = responses
        self.calls = calls
        self.closed = False

    def __enter__(self):
        return self

    def __exit__(self, *exc_info):
        self.closed = True

    def request_status(self, request_id: str) -> RequestStatusResult:
        self.calls.append(("status", request_id))
        result = self.responses[request_id]
        if result.executed:
            outcome = ContractOutcome.APPROVAL_APPROVED
            approval_status = ApprovalStatus.APPROVED
        else:
            outcome = {
                "PENDING": ContractOutcome.APPROVAL_PENDING,
                "REJECTED": ContractOutcome.APPROVAL_REJECTED,
                "EXPIRED": ContractOutcome.APPROVAL_EXPIRED,
                "CONSUMED": ContractOutcome.APPROVAL_CONSUMED,
            }.get(result.approval_status, ContractOutcome.REFUSED)
            approval_status = {
                "PENDING": ApprovalStatus.PENDING,
                "REJECTED": ApprovalStatus.REJECTED,
                "EXPIRED": ApprovalStatus.EXPIRED,
                "CONSUMED": ApprovalStatus.CONSUMED,
            }.get(result.approval_status)
        approval = (
            ApprovalHandle(request_id, approval_status, EXPIRES_AT, "shell.run_approved")
            if approval_status is not None
            else None
        )
        error = None
        if outcome is ContractOutcome.REFUSED:
            error = ContractError("REQUEST_NOT_FOUND", result.message, False)
        elif outcome is not ContractOutcome.APPROVAL_APPROVED:
            error = ContractError(
                outcome.value,
                result.message,
                outcome is ContractOutcome.APPROVAL_PENDING,
            )
        trace_id = f"trc_{request_id}" if outcome is not ContractOutcome.REFUSED else "trc_unknown"
        return RequestStatusResult(request_id, outcome, trace_id, approval, error)

    def run_approved(
        self,
        request_id: str,
        *,
        name: str,
        resume_tool: str | None = None,
    ) -> CommandResult:
        self.calls.append(("resume", request_id))
        assert resume_tool == "shell.run_approved"
        result = self.responses[request_id]
        assert result.name == name
        return result


def backend_factory(responses, calls, roots=None):
    def factory(root):
        if roots is not None:
            roots.append(root)
        return FakeApprovedBackend(root, responses, calls)

    return factory


def test_mcp_scan_with_pending_command_creates_cli_session(
    tmp_path: Path, state_root_dir: Path, monkeypatch
) -> None:
    pending = command_result("Python tests", ("pytest",), "req_tests")
    result = scan_result(tmp_path.resolve(), pending)
    sentinel = object()
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("repo_doctor.cli.create_tool_backend", lambda *args: sentinel)
    monkeypatch.setattr("repo_doctor.cli.scan", lambda *args, **kwargs: result)

    response = CliRunner().invoke(
        app,
        ["scan", ".", "--tool-backend", "mcp", "--trusted-execution"],
    )

    assert response.exit_code == 0, response.output
    assert "Approval required" in response.output
    assert "req_tests" in response.output
    files = list((state_root_dir / "sessions").glob("*.json"))
    assert len(files) == 1
    stored = load_session_file(files[0])
    assert stored.operations[0].request_id == "req_tests"
    assert not (tmp_path / ".repo-doctor").exists()


def test_session_stores_multiple_requests_and_canonical_target(
    tmp_path: Path, state_root_dir: Path
) -> None:
    child = tmp_path / "child"
    child.mkdir()
    noncanonical = child / ".."
    session = pending_session(noncanonical, two=True)
    loaded = load_session(session.session_id)

    assert loaded.target_path == tmp_path.resolve()
    assert [item.request_id for item in loaded.operations] == ["req_tests", "req_lint"]
    assert [item.verification_kind for item in loaded.operations] == ["tests", "lint"]
    raw = session_file_path(session.session_id).read_text(encoding="utf-8")
    assert '"approved"' not in raw.lower()
    assert loaded.schema_version == 2
    assert loaded.session_id == session.session_id


def test_session_write_uses_atomic_replace(
    tmp_path: Path, state_root_dir: Path, monkeypatch
) -> None:
    session = create_scan_session(
        scan_result(tmp_path, command_result("Python tests", ("pytest",), "req_tests"))
    )
    replacements = []
    real_replace = __import__("os").replace

    def recording_replace(source, destination):
        replacements.append((Path(source), Path(destination)))
        real_replace(source, destination)

    monkeypatch.setattr("repo_doctor.sessions.os.replace", recording_replace)
    destination = save_session(session)

    assert replacements == [(replacements[0][0], destination)]
    assert replacements[0][0].suffix == ".tmp"
    assert not replacements[0][0].exists()
    assert destination.is_file()


def test_oversized_scan_update_preserves_previous_file_and_leaves_no_temp(
    tmp_path: Path, state_root_dir: Path
) -> None:
    session = pending_session(tmp_path)
    destination = session_file_path(session.session_id)
    original = destination.read_bytes()
    session.result.potential_bugs = ["x" * 20_000 for _ in range(60)]

    with pytest.raises(SessionError, match="exceeds.*safety limit"):
        save_session(session)

    assert destination.read_bytes() == original
    assert not list(destination.parent.glob(f".{session.session_id}.*.tmp"))


def test_oversized_first_scan_save_leaves_no_file_or_temp(
    tmp_path: Path, state_root_dir: Path
) -> None:
    session = create_scan_session(
        scan_result(tmp_path, command_result("Python tests", ("pytest",), "req_tests"))
    )
    session.result.potential_bugs = ["x" * 20_000 for _ in range(60)]
    destination = session_file_path(session.session_id)

    with pytest.raises(SessionError, match="exceeds.*safety limit"):
        save_session(session)

    assert not destination.exists()
    assert not destination.parent.exists() or not list(
        destination.parent.glob(f".{session.session_id}.*.tmp")
    )


def test_resume_approved_result_updates_report_and_completes(
    tmp_path: Path, state_root_dir: Path
) -> None:
    session = pending_session(tmp_path)
    calls = []
    approved = command_result(
        "Python tests",
        ("pytest",),
        "req_tests",
        status="CONSUMED",
        executed=True,
        stdout="1 passed\n",
    )

    resume_scan_session(
        session,
        backend_factory=backend_factory({"req_tests": approved}, calls),
    )

    loaded = load_session(session.session_id)
    assert calls == [("status", "req_tests"), ("resume", "req_tests")]
    assert loaded.status is SessionStatus.COMPLETED
    assert loaded.operations[0].status is OperationStatus.COMPLETED
    assert loaded.result.commands[0].passed
    report = render_report(loaded.result)
    assert "Python tests: PASS" in report
    assert "1 passed" in report


def test_resume_pending_remains_pending(tmp_path: Path, state_root_dir: Path) -> None:
    session = pending_session(tmp_path)
    calls = []
    pending = command_result("Python tests", ("pytest",), "req_tests")

    resume_scan_session(
        session,
        backend_factory=backend_factory({"req_tests": pending}, calls),
    )

    assert calls == [("status", "req_tests")]
    assert session.status is SessionStatus.PENDING
    assert session.operations[0].status is OperationStatus.PENDING
    assert "APPROVAL REQUIRED" in render_report(session.result)


def test_resume_unknown_request_is_reported_clearly(tmp_path: Path, state_root_dir: Path) -> None:
    session = pending_session(tmp_path)
    calls = []
    unknown = CommandResult(
        name="Python tests",
        command=("pytest",),
        exit_code=126,
        stdout="",
        stderr="",
        duration=0.1,
        request_id="req_tests",
        message="Unknown approval request: req_tests",
        executed=False,
        trace_id="trc_req_tests",
        toolhub_outcome="REFUSED",
        error_code="REQUEST_NOT_FOUND",
        error_retryable=False,
    )

    resume_scan_session(
        session,
        backend_factory=backend_factory({"req_tests": unknown}, calls),
    )

    assert session.operations[0].status is OperationStatus.UNKNOWN
    report = render_report(session.result)
    assert "Python tests: UNAVAILABLE" in report
    assert "Unknown approval request: req_tests" in report
    assert "Python tests: FAIL" not in report


@pytest.mark.parametrize(
    ("toolhub_status", "operation_status"),
    [
        ("REJECTED", OperationStatus.REJECTED),
        ("EXPIRED", OperationStatus.EXPIRED),
        ("CONSUMED", OperationStatus.CONSUMED),
    ],
)
def test_resume_terminal_toolhub_state_is_distinct_from_failure(
    tmp_path: Path,
    state_root_dir: Path,
    toolhub_status: str,
    operation_status: OperationStatus,
) -> None:
    session = pending_session(tmp_path)
    calls = []
    result = command_result("Python tests", ("pytest",), "req_tests", status=toolhub_status)

    resume_scan_session(
        session,
        backend_factory=backend_factory({"req_tests": result}, calls),
    )

    assert calls == [("status", "req_tests")]
    assert session.operations[0].status is operation_status
    assert session.status is SessionStatus.UNABLE_TO_CONTINUE
    report = render_report(session.result)
    assert f"Python tests: {toolhub_status}" in report
    assert "Python tests: FAIL" not in report


def test_two_requests_make_partial_progress_and_persist(
    tmp_path: Path, state_root_dir: Path
) -> None:
    session = pending_session(tmp_path, two=True)
    calls = []
    responses = {
        "req_tests": command_result(
            "Python tests", ("pytest",), "req_tests", status="CONSUMED", executed=True
        ),
        "req_lint": command_result("Python lint", ("ruff", "check", "."), "req_lint"),
    }

    resume_scan_session(
        session,
        backend_factory=backend_factory(responses, calls),
    )

    loaded = load_session(session.session_id)
    assert calls == [
        ("status", "req_tests"),
        ("resume", "req_tests"),
        ("status", "req_lint"),
    ]
    assert loaded.status is SessionStatus.PARTIAL
    assert [item.status for item in loaded.operations] == [
        OperationStatus.COMPLETED,
        OperationStatus.PENDING,
    ]
    assert [item.request_id for item in loaded.pending_operations] == ["req_lint"]


def test_repeated_resume_does_not_reexecute_completed_operation(
    tmp_path: Path, state_root_dir: Path
) -> None:
    session = pending_session(tmp_path)
    calls = []
    approved = command_result(
        "Python tests", ("pytest",), "req_tests", status="CONSUMED", executed=True
    )
    factory = backend_factory({"req_tests": approved}, calls)

    resume_scan_session(session, backend_factory=factory)
    resume_scan_session(session, backend_factory=lambda _: pytest.fail("backend was reopened"))

    assert calls == [("status", "req_tests"), ("resume", "req_tests")]


def test_trace_mismatch_fails_before_approved_tool_call(
    tmp_path: Path, state_root_dir: Path
) -> None:
    session = pending_session(tmp_path)
    calls = []
    approved = command_result(
        "Python tests", ("pytest",), "req_tests", status="CONSUMED", executed=True
    )
    backend = FakeApprovedBackend(tmp_path, {"req_tests": approved}, calls)
    real_status = backend.request_status

    def mismatched(request_id: str) -> RequestStatusResult:
        status = real_status(request_id)
        return RequestStatusResult(
            status.request_id,
            status.outcome,
            "trc_different",
            status.approval,
            status.error,
        )

    backend.request_status = mismatched

    with pytest.raises(SessionError, match="trace_id changed"):
        resume_scan_session(session, backend_factory=lambda _root: backend)

    assert calls == [("status", "req_tests")]


def test_session_cannot_inject_arbitrary_resume_tool(tmp_path: Path, state_root_dir: Path) -> None:
    session = pending_session(tmp_path)
    path = session_file_path(session.session_id)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["operations"][0]["resume_tool"] = "attacker.execute"
    payload["scan"]["commands"][0]["resume_tool"] = "attacker.execute"
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(SessionError, match="unsafe resume_tool|must be 'shell.run_approved'"):
        load_session(session.session_id)


def test_malformed_session_has_clear_error(tmp_path: Path, state_root_dir: Path) -> None:
    session_id = "a" * 32
    path = session_file_path(session_id)
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps({"schema_version": 1}), encoding="utf-8")

    with pytest.raises(SessionError, match="missing or unexpected fields"):
        load_session_file(path, expected_id=session_id)


def test_schema_v1_pending_session_migrates_without_approval_authority(
    tmp_path: Path, state_root_dir: Path
) -> None:
    session = pending_session(tmp_path)
    path = session_file_path(session.session_id)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["schema_version"] = 1
    for operation in payload["operations"]:
        for field in ("toolhub_outcome", "resume_tool", "expires_at", "trace_id"):
            operation.pop(field)
    for command in payload["scan"]["commands"]:
        for field in (
            "toolhub_outcome",
            "resume_tool",
            "expires_at",
            "trace_id",
            "error_code",
            "error_retryable",
        ):
            command.pop(field)
    path.write_text(json.dumps(payload), encoding="utf-8")

    migrated = load_session(session.session_id)

    assert migrated.schema_version == 2
    assert migrated.operations[0].status is OperationStatus.UNKNOWN
    assert not migrated.pending_operations
    assert migrated.status is SessionStatus.UNABLE_TO_CONTINUE
    assert migrated.operations[0].resume_tool is None
    assert migrated.operations[0].toolhub_outcome is None
    assert migrated.result.commands[0].approval_status is None
    assert migrated.result.commands[0].resume_tool is None


def test_terminal_schema_v1_scan_session_remains_readable(
    tmp_path: Path, state_root_dir: Path
) -> None:
    session = pending_session(tmp_path)
    path = session_file_path(session.session_id)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["schema_version"] = 1
    payload["status"] = "completed"
    payload["operations"][0]["status"] = "completed"
    command = payload["scan"]["commands"][0]
    command.update(
        {
            "executed": True,
            "approval_required": False,
            "exit_code": 0,
            "toolhub_approval_status": "CONSUMED",
        }
    )
    for operation in payload["operations"]:
        for field in ("toolhub_outcome", "resume_tool", "expires_at", "trace_id"):
            operation.pop(field)
    for item in payload["scan"]["commands"]:
        for field in (
            "toolhub_outcome",
            "resume_tool",
            "expires_at",
            "trace_id",
            "error_code",
            "error_retryable",
        ):
            item.pop(field)
    path.write_text(json.dumps(payload), encoding="utf-8")

    migrated = load_session(session.session_id)

    assert migrated.schema_version == 2
    assert migrated.status is SessionStatus.COMPLETED
    assert migrated.operations[0].status is OperationStatus.COMPLETED
    assert migrated.operations[0].resume_tool is None
    assert migrated.result.commands[0].executed is True
    assert migrated.result.commands[0].approval_status == "CONSUMED"
    assert not migrated.pending_operations


def test_future_session_schema_fails_closed(tmp_path: Path, state_root_dir: Path) -> None:
    session = pending_session(tmp_path)
    path = session_file_path(session.session_id)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["schema_version"] = 999
    path.write_text(json.dumps(payload), encoding="utf-8")

    with pytest.raises(SessionError, match="Unsupported session schema version 999"):
        load_session(session.session_id)


def test_resume_uses_only_stored_target_path(
    tmp_path: Path, state_root_dir: Path, monkeypatch
) -> None:
    target = tmp_path / "target"
    other = tmp_path / "other"
    target.mkdir()
    other.mkdir()
    session = pending_session(target)
    calls = []
    roots = []
    pending = command_result("Python tests", ("pytest",), "req_tests")
    monkeypatch.chdir(other)

    resume_scan_session(
        session,
        backend_factory=backend_factory({"req_tests": pending}, calls, roots),
    )

    assert roots == [target.resolve()]
    response = CliRunner().invoke(
        app,
        ["resume", session.session_id, "--repository-path", str(other)],
    )
    assert response.exit_code != 0


def test_session_file_outside_state_root_is_rejected(tmp_path: Path, state_root_dir: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    session = pending_session(target)
    original = session_file_path(session.session_id)
    moved = tmp_path / "elsewhere" / f"{session.session_id}.json"
    moved.parent.mkdir(parents=True)
    moved.write_bytes(original.read_bytes())

    with pytest.raises(SessionError, match="state directory"):
        load_session_file(moved)


def test_session_file_with_wrong_name_inside_state_root_is_rejected(
    tmp_path: Path, state_root_dir: Path
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    session = pending_session(target)
    original = session_file_path(session.session_id)
    renamed = state_root_dir / "sessions" / f"{'b' * 32}.json"
    renamed.write_bytes(original.read_bytes())

    with pytest.raises(SessionError, match="state directory"):
        load_session_file(renamed)
    with pytest.raises(SessionError, match="does not match"):
        load_session(renamed.stem)


def test_session_creation_leaves_target_repository_untouched(
    tmp_path: Path, state_root_dir: Path
) -> None:
    target = tmp_path / "target"
    target.mkdir()

    session = pending_session(target)

    assert not (target / ".repo-doctor").exists()
    assert list(target.iterdir()) == []
    assert session_file_path(session.session_id).is_file()


def test_clean_target_git_status_remains_clean(tmp_path: Path, state_root_dir: Path) -> None:
    target = tmp_path / "target"
    target.mkdir()
    subprocess.run(["git", "init", "-q", str(target)], check=True)
    (target / "app.py").write_text("print('ok')\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(target), "add", "app.py"], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(target),
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

    session = pending_session(target)

    status = subprocess.run(
        ["git", "-C", str(target), "status", "--porcelain"],
        check=True,
        capture_output=True,
        text=True,
    )
    assert status.stdout == ""
    assert not (target / ".repo-doctor").exists()
    assert session_file_path(session.session_id).is_file()


def test_two_target_repositories_do_not_collide(tmp_path: Path, state_root_dir: Path) -> None:
    target_a = tmp_path / "repository-a"
    target_b = tmp_path / "repository-b"
    target_a.mkdir()
    target_b.mkdir()

    session_a = pending_session(target_a)
    session_b = pending_session(target_b)

    assert session_a.session_id != session_b.session_id
    loaded_a = load_session(session_a.session_id)
    loaded_b = load_session(session_b.session_id)
    assert loaded_a.target_path == target_a.resolve()
    assert loaded_b.target_path == target_b.resolve()
    files = sorted((state_root_dir / "sessions").glob("*.json"))
    assert len(files) == 2
    assert files == sorted(
        [session_file_path(session_a.session_id), session_file_path(session_b.session_id)]
    )


def test_state_root_override_controls_session_location(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "target"
    target.mkdir()
    override = tmp_path / "custom-state"
    monkeypatch.setenv("REPO_DOCTOR_STATE_ROOT", str(override))

    session = create_scan_session(
        scan_result(target, command_result("Python tests", ("pytest",), "req_tests"))
    )
    destination = save_session(session)

    assert destination == override / "sessions" / f"{session.session_id}.json"
    assert destination.is_file()
    assert load_session(session.session_id).session_id == session.session_id
    assert not (target / ".repo-doctor").exists()


def test_state_root_override_must_be_absolute(tmp_path: Path, monkeypatch) -> None:
    target = tmp_path / "target"
    target.mkdir()
    monkeypatch.setenv("REPO_DOCTOR_STATE_ROOT", "relative/state")

    session = create_scan_session(
        scan_result(target, command_result("Python tests", ("pytest",), "req_tests"))
    )
    with pytest.raises(SessionError, match="absolute"):
        save_session(session)
    with pytest.raises(SessionError, match="absolute"):
        load_session("a" * 32)


def test_default_state_root_is_user_level_and_absolute(monkeypatch) -> None:
    monkeypatch.delenv("REPO_DOCTOR_STATE_ROOT", raising=False)

    root = state_root()

    assert root == default_state_root()
    assert root.is_absolute()
