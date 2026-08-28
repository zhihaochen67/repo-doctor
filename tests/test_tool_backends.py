import hashlib
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest
from typer.testing import CliRunner

from repo_doctor.analyzer import is_utf8_text_file
from repo_doctor.backends import (
    TOOLHUB_PROJECT_ENV,
    FileReadError,
    LocalToolBackend,
    MCPToolBackend,
    ToolBackendKind,
    ToolBackendStartupError,
    ToolCallError,
    _configured_toolhub_project,
    _toolhub_process,
    create_tool_backend,
)
from repo_doctor.cli import app
from repo_doctor.models import ScanResult
from repo_doctor.report import render_report
from repo_doctor.scanner import scan
from repo_doctor.sessions import load_session_file

EXPIRES_AT = "2099-01-01T00:00:00Z"


def prepare_toolhub_project(project: Path, *, platform_name: str | None = None) -> Path:
    platform = platform_name or os.name
    interpreter = (
        project / ".venv" / "Scripts" / "python.exe"
        if platform == "nt"
        else project / ".venv" / "bin" / "python"
    )
    interpreter.parent.mkdir(parents=True, exist_ok=True)
    interpreter.write_bytes(b"")
    return project


def capabilities_response(version: str = "1.0") -> dict:
    return {
        "contract_version": version,
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


class FakeMCPClient:
    def __init__(self, responses=None, *, startup_error=None, call_error=None):
        self.responses = {"toolhub.capabilities": capabilities_response()}
        self.responses.update(responses or {})
        self.startup_error = startup_error
        self.call_error = call_error
        self.started = False
        self.closed = False
        self.calls = []

    def start(self):
        self.started = True
        if self.startup_error:
            raise self.startup_error

    def call_tool(self, name, arguments):
        self.calls.append((name, arguments))
        if self.call_error and name != "toolhub.capabilities":
            raise self.call_error
        return self.responses[name]

    def close(self):
        self.closed = True


def make_backend(tmp_path: Path, client: FakeMCPClient):
    captured = {}
    project = prepare_toolhub_project(tmp_path / "toolhub")

    def factory(process):
        captured["process"] = process
        return client

    backend = MCPToolBackend(
        tmp_path,
        toolhub_project=project,
        client_factory=factory,
    )
    return backend, captured


def file_response(content: str = "hello\n") -> dict:
    data = content.encode()
    return {
        "path": "app.py",
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "content": content,
    }


def status_response() -> dict:
    return {
        "path": ".",
        "branch": "main",
        "clean": False,
        "entries": [{"code": " M", "path": "app.py"}],
        "raw": "## main\n M app.py\n",
    }


def diff_response() -> dict:
    return {
        "path": "app.py",
        "staged": False,
        "additions": 1,
        "deletions": 0,
        "binary": False,
        "raw": "+fixed\n",
    }


def shell_response(*, pending: bool = False) -> dict:
    if pending:
        return {
            "outcome": "APPROVAL_REQUIRED",
            "trace_id": "trc_pending",
            "approval": {
                "request_id": "req_pending",
                "status": "PENDING",
                "expires_at": EXPIRES_AT,
                "resume_tool": "shell.run_approved",
            },
            "error": None,
            "program": "pytest",
            "args": [],
            "cwd": ".",
            "risk": "MEDIUM",
            "risk_reason": "Running tests executes repository code.",
            "executed": False,
            "returncode": None,
            "stdout": "",
            "stderr": "",
            "timed_out": False,
            "request_id": "req_pending",
            "approval_status": "PENDING",
            "message": "Approval required (PENDING).",
        }
    return {
        "outcome": "SUCCEEDED",
        "trace_id": "trc_immediate",
        "approval": None,
        "error": None,
        "program": "python",
        "args": ["--version"],
        "cwd": ".",
        "risk": "LOW",
        "risk_reason": "Interpreter version query.",
        "executed": True,
        "returncode": 0,
        "stdout": "Python 3.13\n",
        "stderr": "",
        "timed_out": False,
        "request_id": None,
        "approval_status": None,
        "message": "",
    }


def approved_shell_response(*, status: str = "CONSUMED", executed: bool = True) -> dict:
    outcomes = {
        "PENDING": "APPROVAL_PENDING",
        "APPROVED": "APPROVAL_APPROVED",
        "REJECTED": "APPROVAL_REJECTED",
        "EXPIRED": "APPROVAL_EXPIRED",
        "CONSUMED": "SUCCEEDED" if executed else "APPROVAL_CONSUMED",
    }
    return {
        "outcome": outcomes[status],
        "trace_id": "trc_pending",
        "approval": {
            "request_id": "req_pending",
            "status": status,
            "expires_at": EXPIRES_AT,
            "resume_tool": "shell.run_approved",
        },
        "error": None
        if executed or status == "APPROVED"
        else {
            "code": f"APPROVAL_{status}",
            "message": f"Request is {status}.",
            "retryable": status == "PENDING",
        },
        "program": "pytest",
        "args": [],
        "cwd": ".",
        "risk": "MEDIUM",
        "risk_reason": "Running tests executes repository code.",
        "executed": executed,
        "returncode": 0 if executed else None,
        "stdout": "1 passed\n" if executed else "",
        "stderr": "",
        "timed_out": False,
        "request_id": "req_pending",
        "approval_status": status,
        "message": "" if executed else f"Request is {status}; cannot execute.",
    }


def shell_outcome_response(outcome: str) -> dict:
    executed = outcome in {"SUCCEEDED", "COMMAND_FAILED", "TIMED_OUT"}
    returncode = {"SUCCEEDED": 0, "COMMAND_FAILED": 3}.get(outcome)
    return {
        "outcome": outcome,
        "trace_id": f"trc_{outcome.lower()}",
        "approval": None,
        "error": (
            None
            if outcome == "SUCCEEDED"
            else {"code": outcome, "message": "diagnostic", "retryable": False}
        ),
        "program": "python",
        "args": ["--version"],
        "cwd": ".",
        "executed": executed,
        "returncode": returncode,
        "stdout": "ok\n" if outcome == "SUCCEEDED" else "",
        "stderr": "failed\n" if outcome == "COMMAND_FAILED" else "",
        "timed_out": outcome == "TIMED_OUT",
        "request_id": None,
        "approval_status": None,
        "message": "diagnostic",
    }


def test_local_backend_is_default_and_preserves_local_cli(tmp_path: Path, monkeypatch) -> None:
    observed = {}

    def fake_scan(root, timeout):
        observed["root"] = root
        return ScanResult(root.resolve(), [], 0, 0, [])

    def unexpected_factory(*args, **kwargs):
        raise AssertionError("default local CLI must not initialize MCP")

    monkeypatch.setattr("repo_doctor.cli.scan", fake_scan)
    monkeypatch.setattr("repo_doctor.cli.create_tool_backend", unexpected_factory)

    response = CliRunner().invoke(app, ["scan", str(tmp_path)])

    assert response.exit_code == 0, response.output
    assert observed["root"] == tmp_path
    assert isinstance(create_tool_backend(ToolBackendKind.LOCAL, tmp_path), LocalToolBackend)


def test_cli_backend_selection_passes_mcp_backend_to_scan(tmp_path: Path, monkeypatch) -> None:
    sentinel = object()
    observed = {}

    monkeypatch.setattr(
        "repo_doctor.cli.create_tool_backend",
        lambda kind, root: observed.update(kind=kind, root=root) or sentinel,
    )

    def fake_scan(root, timeout, backend=None):
        observed["backend"] = backend
        return ScanResult(root.resolve(), [], 0, 0, [])

    monkeypatch.setattr("repo_doctor.cli.scan", fake_scan)

    response = CliRunner().invoke(
        app,
        ["scan", str(tmp_path), "--tool-backend", "mcp"],
    )

    assert response.exit_code == 0, response.output
    assert observed == {
        "kind": ToolBackendKind.MCP,
        "root": tmp_path,
        "backend": sentinel,
    }


def test_mcp_launch_configuration_injects_one_absolute_workspace(
    tmp_path: Path, monkeypatch
) -> None:
    inherited = tmp_path / "wrong"
    monkeypatch.setenv("TOOLHUB_WORKSPACE_ROOT", str(inherited))
    client = FakeMCPClient()
    backend, captured = make_backend(tmp_path, client)
    process = captured["process"]

    assert Path(process.env["TOOLHUB_WORKSPACE_ROOT"]).is_absolute()
    assert Path(process.env["TOOLHUB_WORKSPACE_ROOT"]) == tmp_path.resolve()
    assert process.cwd.is_absolute()
    assert process.args == ("-m", "mcp_toolhub", "serve")
    backend.close()


def test_explicit_absolute_toolhub_project_is_canonical_and_project_bound(
    tmp_path: Path, monkeypatch
) -> None:
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    project = prepare_toolhub_project(tmp_path / "toolhub")
    monkeypatch.setenv(TOOLHUB_PROJECT_ENV, str(project))

    configured = _configured_toolhub_project(None)
    process = _toolhub_process(workspace)

    assert configured == project.resolve()
    assert Path(process.command) == (project / ".venv" / "Scripts" / "python.exe").resolve()
    assert process.args == ("-m", "mcp_toolhub", "serve")
    assert process.cwd == project.resolve()
    assert Path(process.env["TOOLHUB_WORKSPACE_ROOT"]) == workspace.resolve()


def test_toolhub_project_rejects_relative_missing_and_file_paths(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv(TOOLHUB_PROJECT_ENV, "relative/toolhub")
    with pytest.raises(ToolBackendStartupError, match="must be an absolute path"):
        _configured_toolhub_project(None)

    missing = (tmp_path / "missing").resolve()
    monkeypatch.setenv(TOOLHUB_PROJECT_ENV, str(missing))
    with pytest.raises(ToolBackendStartupError, match="does not exist"):
        _configured_toolhub_project(None)

    file_path = tmp_path / "not-a-directory"
    file_path.write_text("not a project", encoding="utf-8")
    monkeypatch.setenv(TOOLHUB_PROJECT_ENV, str(file_path.resolve()))
    with pytest.raises(ToolBackendStartupError, match="not a directory"):
        _configured_toolhub_project(None)

    monkeypatch.setenv(TOOLHUB_PROJECT_ENV, "")
    with pytest.raises(ToolBackendStartupError, match="must be an absolute path"):
        _configured_toolhub_project(None)


def test_toolhub_bootstrap_never_uses_path_or_global_python(tmp_path: Path, monkeypatch) -> None:
    project = tmp_path / "toolhub"
    project.mkdir()
    global_bin = tmp_path / "global-bin"
    global_bin.mkdir()
    (global_bin / "mcp-toolhub.exe").write_bytes(b"")
    global_python = tmp_path / "global-python.exe"
    global_python.write_bytes(b"")
    monkeypatch.setenv("PATH", str(global_bin))
    monkeypatch.setattr(sys, "executable", str(global_python))

    with pytest.raises(ToolBackendStartupError, match="will not use PATH/global fallbacks"):
        _toolhub_process(tmp_path, project)


def test_toolhub_bootstrap_removes_python_injection_and_preserves_state(
    tmp_path: Path, monkeypatch
) -> None:
    project = prepare_toolhub_project(tmp_path / "toolhub")
    state_root = tmp_path / "toolhub-state"
    monkeypatch.setenv("PYTHONPATH", str(tmp_path / "attacker"))
    monkeypatch.setenv("PYTHONHOME", str(tmp_path / "foreign-python"))
    monkeypatch.setenv("PYTHONSTARTUP", str(tmp_path / "startup.py"))
    monkeypatch.setenv("PYTHONUSERBASE", str(tmp_path / "userbase"))
    monkeypatch.setenv("PYTHONPLATLIBDIR", "attacker-lib")
    monkeypatch.setenv("PYTHONPYCACHEPREFIX", str(tmp_path / "foreign-cache"))
    monkeypatch.setenv("TOOLHUB_STATE_ROOT", str(state_root))

    process = _toolhub_process(tmp_path, project)

    assert not {
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONSTARTUP",
        "PYTHONUSERBASE",
        "PYTHONPLATLIBDIR",
        "PYTHONPYCACHEPREFIX",
    }.intersection(name.upper() for name in process.env)
    assert "PYTHONNOUSERSITE" not in process.env
    assert "PYTHONSAFEPATH" not in process.env
    assert process.env["TOOLHUB_STATE_ROOT"] == str(state_root)


def test_toolhub_bootstrap_selects_posix_project_venv_layout(tmp_path: Path) -> None:
    project = prepare_toolhub_project(tmp_path / "toolhub", platform_name="posix")

    process = _toolhub_process(tmp_path, project, platform_name="posix")

    assert Path(process.command) == (project / ".venv" / "bin" / "python").resolve()
    assert process.args == ("-m", "mcp_toolhub", "serve")
    assert process.cwd == project.resolve()


@pytest.mark.skipif(os.name != "nt", reason="Windows-only default policy")
def test_windows_toolhub_default_is_used_only_when_existing(tmp_path: Path, monkeypatch) -> None:
    project = prepare_toolhub_project(tmp_path / "windows-default")
    monkeypatch.delenv(TOOLHUB_PROJECT_ENV, raising=False)
    monkeypatch.setattr("repo_doctor.backends.DEFAULT_WINDOWS_TOOLHUB_PROJECT", project)
    assert _configured_toolhub_project(None) == project.resolve()

    missing = tmp_path / "missing-default"
    monkeypatch.setattr("repo_doctor.backends.DEFAULT_WINDOWS_TOOLHUB_PROJECT", missing)
    with pytest.raises(ToolBackendStartupError, match=f"Set {TOOLHUB_PROJECT_ENV}"):
        _configured_toolhub_project(None)


def test_mcp_result_mapping_and_calls_never_include_a_root(tmp_path: Path) -> None:
    client = FakeMCPClient(
        {
            "filesystem.read_file": file_response(),
            "git.status": status_response(),
            "git.diff": diff_response(),
            "shell.run": shell_response(),
        }
    )
    backend, _ = make_backend(tmp_path, client)

    with backend:
        read = backend.read_file("app.py")
        status = backend.git_status()
        diff = backend.git_diff("app.py")
        command = backend.run_command("Python version", ("python", "--version"))

    assert read.content == "hello\n"
    assert read.sha256 == file_response()["sha256"]
    assert status.branch == "main"
    assert status.entries[0].path == "app.py"
    assert diff.additions == 1
    assert "+fixed" in diff.raw
    assert command.passed
    assert command.stdout == "Python 3.13\n"
    assert client.started and client.closed
    assert all(
        "root" not in arguments and "workspace_root" not in arguments
        for _, arguments in client.calls
    )


def test_pending_approval_is_structured_and_visible_in_report(tmp_path: Path) -> None:
    client = FakeMCPClient({"shell.run": shell_response(pending=True)})
    backend, _ = make_backend(tmp_path, client)

    with backend:
        result = backend.run_command("Python tests", ("pytest",))

    assert not result.passed
    assert result.approval_required
    assert result.request_id == "req_pending"
    assert result.approval_status == "PENDING"
    scan = ScanResult(tmp_path, ["Python"], 0, 0, [], commands=[result])
    report = render_report(scan)
    assert "APPROVAL REQUIRED" in report
    assert "req_pending" in report


@pytest.mark.parametrize(
    ("outcome", "exit_code", "executed", "timed_out"),
    [
        ("SUCCEEDED", 0, True, False),
        ("COMMAND_FAILED", 3, True, False),
        ("TIMED_OUT", 124, True, True),
        ("REFUSED", 126, False, False),
        ("FAILED", 126, False, False),
    ],
)
def test_shell_contract_outcomes_map_deterministically(
    tmp_path: Path,
    outcome: str,
    exit_code: int,
    executed: bool,
    timed_out: bool,
) -> None:
    client = FakeMCPClient({"shell.run": shell_outcome_response(outcome)})
    backend, _ = make_backend(tmp_path, client)

    with backend:
        result = backend.run_command("Python", ("python", "--version"))

    assert result.toolhub_outcome == outcome
    assert result.exit_code == exit_code
    assert result.executed is executed
    assert result.timed_out is timed_out
    assert not result.approval_required


def test_mcp_run_approved_calls_only_request_id_and_maps_real_result(tmp_path: Path) -> None:
    client = FakeMCPClient({"shell.run_approved": approved_shell_response()})
    backend, _ = make_backend(tmp_path, client)

    with backend:
        result = backend.run_approved("req_pending", name="Python tests")

    assert client.calls == [
        ("toolhub.capabilities", {}),
        ("shell.run_approved", {"request_id": "req_pending"}),
    ]
    assert result.passed
    assert result.executed
    assert result.command == ("pytest",)
    assert result.request_id == "req_pending"
    assert result.approval_status == "CONSUMED"
    assert result.stdout == "1 passed\n"


def test_mcp_request_status_is_separate_and_validates_declared_resume_tool(
    tmp_path: Path,
) -> None:
    status = {
        "outcome": "APPROVAL_PENDING",
        "trace_id": "trc_pending",
        "approval": {
            "request_id": "req_pending",
            "status": "PENDING",
            "expires_at": EXPIRES_AT,
            "resume_tool": "shell.run_approved",
        },
        "error": {
            "code": "APPROVAL_PENDING",
            "message": "Pending human review.",
            "retryable": True,
        },
        "request_id": "req_pending",
    }
    client = FakeMCPClient({"toolhub.request_status": status})
    backend, _ = make_backend(tmp_path, client)

    with backend:
        result = backend.request_status("req_pending")

    assert result.outcome.value == "APPROVAL_PENDING"
    assert client.calls == [
        ("toolhub.capabilities", {}),
        ("toolhub.request_status", {"request_id": "req_pending"}),
    ]

    status["approval"]["resume_tool"] = "attacker.execute"
    client = FakeMCPClient({"toolhub.request_status": status})
    backend, _ = make_backend(tmp_path, client)
    with backend, pytest.raises(ToolCallError, match="undeclared resume_tool"):
        backend.request_status("req_pending")


def test_mcp_scan_routes_reads_and_discovered_commands_through_backend(tmp_path: Path) -> None:
    (tmp_path / "pyproject.toml").write_text("[tool.ruff]\n", encoding="utf-8")
    (tmp_path / "README.md").write_text("# Fixture\n", encoding="utf-8")
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_app.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")
    client = FakeMCPClient(
        {
            "filesystem.read_file": file_response("line\n"),
            "shell.run": shell_response(pending=True),
        }
    )
    backend, _ = make_backend(tmp_path, client)

    result = scan(tmp_path, backend=backend)

    names = [name for name, _ in client.calls]
    assert names.count("filesystem.read_file") == 3
    assert names.count("shell.run") == 2
    assert all(command.approval_required for command in result.commands)
    assert result.deterministic_score == 100
    assert all(arguments["cwd"] == "." for name, arguments in client.calls if name == "shell.run")
    assert client.closed


def test_local_and_mcp_scans_share_text_and_binary_eligibility(tmp_path: Path) -> None:
    text = tmp_path / "README.md"
    text.write_text("# Café\n", encoding="utf-8")
    binary = tmp_path / "image.png"
    binary.write_bytes(b"\x89PNG\r\n\x1a\n\x00\xff")

    class RecordingLocalBackend(LocalToolBackend):
        def __init__(self, root: Path):
            super().__init__(root)
            self.read_paths = []

        def read_file(self, path: str):
            self.read_paths.append(path)
            return super().read_file(path)

    local_backend = RecordingLocalBackend(tmp_path)
    local_result = scan(tmp_path, backend=local_backend)
    client = FakeMCPClient({"filesystem.read_file": file_response("# Café\n")})
    mcp_backend, _ = make_backend(tmp_path, client)
    mcp_result = scan(tmp_path, backend=mcp_backend)

    mcp_read_paths = [
        arguments["path"] for name, arguments in client.calls if name == "filesystem.read_file"
    ]
    assert local_backend.read_paths == ["README.md"]
    assert mcp_read_paths == ["README.md"]
    assert local_result.files == mcp_result.files == 2
    assert local_result.lines == mcp_result.lines == 1
    assert is_utf8_text_file(text)
    assert not is_utf8_text_file(binary)


def test_mcp_startup_failure_is_actionable_and_cleanup_is_attempted(tmp_path: Path) -> None:
    client = FakeMCPClient(startup_error=FileNotFoundError("mcp executable missing"))
    backend, _ = make_backend(tmp_path, client)

    with pytest.raises(ToolBackendStartupError, match="Could not start MCP ToolHub"):
        backend.read_file("app.py")

    assert client.closed


def test_mcp_startup_requires_valid_contract_v1_capabilities(tmp_path: Path) -> None:
    missing = FakeMCPClient()
    missing.responses.pop("toolhub.capabilities")
    backend, _ = make_backend(tmp_path, missing)

    with pytest.raises(ToolBackendStartupError, match="toolhub.capabilities"):
        backend.read_file("app.py")
    assert missing.calls == [("toolhub.capabilities", {})]
    assert missing.closed

    malformed = FakeMCPClient()
    malformed.responses["toolhub.capabilities"] = {"contract_version": "1.0"}
    backend, _ = make_backend(tmp_path, malformed)
    with pytest.raises(ToolBackendStartupError, match="Contract V1"):
        backend.read_file("app.py")
    assert malformed.closed


def test_mcp_call_failure_is_actionable(tmp_path: Path) -> None:
    client = FakeMCPClient(call_error=RuntimeError("connection closed"))
    backend, _ = make_backend(tmp_path, client)

    with (
        backend,
        pytest.raises(
            FileReadError,
            match=(
                "Could not read repository file 'app.py' via MCP ToolHub: "
                "ToolHub call filesystem.read_file failed: connection closed"
            ),
        ),
    ):
        backend.read_file("app.py")

    assert client.closed


def test_mcp_scan_does_not_mistake_transport_failure_for_binary(tmp_path: Path) -> None:
    (tmp_path / "README.md").write_text("# Fixture\n", encoding="utf-8")
    client = FakeMCPClient(call_error=RuntimeError("connection closed"))
    backend, _ = make_backend(tmp_path, client)

    with pytest.raises(FileReadError, match="README.md.*connection closed"):
        scan(tmp_path, backend=backend)

    assert client.calls == [
        ("toolhub.capabilities", {}),
        ("filesystem.read_file", {"path": "README.md"}),
    ]
    assert client.closed


def test_mcp_workspace_rejection_remains_fatal_and_names_path(tmp_path: Path) -> None:
    client = FakeMCPClient(call_error=RuntimeError("workspace access denied"))
    backend, _ = make_backend(tmp_path, client)

    with (
        backend,
        pytest.raises(FileReadError, match="app.py.*workspace access denied"),
    ):
        backend.read_file("app.py")

    assert client.closed


def test_mcp_malformed_read_result_names_attempted_path(tmp_path: Path) -> None:
    client = FakeMCPClient({"filesystem.read_file": {"content": "hello"}})
    backend, _ = make_backend(tmp_path, client)

    with (
        backend,
        pytest.raises(FileReadError, match="invalid filesystem.read_file result.*app.py"),
    ):
        backend.read_file("app.py")

    assert client.closed


def test_mcp_context_closes_after_caller_exception(tmp_path: Path) -> None:
    client = FakeMCPClient()
    backend, _ = make_backend(tmp_path, client)

    with pytest.raises(RuntimeError, match="caller failed"):
        with backend:
            raise RuntimeError("caller failed")

    assert client.closed


def test_mcp_backend_rejects_absolute_or_traversing_call_paths(tmp_path: Path) -> None:
    client = FakeMCPClient()
    backend, _ = make_backend(tmp_path, client)

    with pytest.raises(ToolCallError, match="relative"):
        backend.read_file(str((tmp_path / "app.py").resolve()))
    with pytest.raises(ToolCallError, match="traverse"):
        backend.read_file("../app.py")

    assert client.calls == []


@pytest.mark.integration
def test_real_toolhub_read_and_git_round_trip(tmp_path: Path, monkeypatch) -> None:
    if os.environ.get("REPO_DOCTOR_RUN_TOOLHUB_INTEGRATION") != "1":
        pytest.skip("set REPO_DOCTOR_RUN_TOOLHUB_INTEGRATION=1 to run real ToolHub integration")
    toolhub = Path(r"D:\mcp-toolhub")
    executable = toolhub / ".venv" / "Scripts" / "python.exe"
    if not executable.is_file():
        pytest.skip(r"real ToolHub is unavailable at D:\mcp-toolhub")
    try:
        import mcp  # noqa: F401
    except ImportError:
        pytest.skip("the Repo Doctor test interpreter does not have the MCP client installed")

    repository = tmp_path / "repository"
    repository.mkdir()
    subprocess.run(["git", "init", "-q", str(repository)], check=True)
    target = repository / "app.py"
    target.write_text("before\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(repository), "add", "app.py"], check=True)
    target.write_text("before\nafter\n", encoding="utf-8")

    state = tmp_path / "toolhub-state"
    monkeypatch.setenv(TOOLHUB_PROJECT_ENV, str(toolhub.resolve()))
    monkeypatch.setenv("TOOLHUB_STATE_ROOT", str(state))

    with MCPToolBackend(repository, toolhub_project=toolhub) as backend:
        read = backend.read_file("app.py")
        status = backend.git_status()
        diff = backend.git_diff("app.py")

    assert read.content == "before\nafter\n"
    assert any(entry.path == "app.py" for entry in status.entries)
    assert "+after" in diff.raw


@pytest.mark.integration
def test_real_toolhub_approval_resume_and_replay_protection(tmp_path: Path, monkeypatch) -> None:
    if os.environ.get("REPO_DOCTOR_RUN_TOOLHUB_INTEGRATION") != "1":
        pytest.skip("set REPO_DOCTOR_RUN_TOOLHUB_INTEGRATION=1 to run real ToolHub integration")
    toolhub = Path(r"D:\mcp-toolhub")
    production_python = toolhub / ".venv" / "Scripts" / "python.exe"
    admin = toolhub / ".venv" / "Scripts" / "mcp-toolhub-admin.exe"
    if not all(path.is_file() for path in (production_python, admin)):
        pytest.skip(r"real ToolHub is unavailable at D:\mcp-toolhub")

    repository = tmp_path / "repository"
    repository.mkdir()
    (repository / "requirements.txt").write_text("", encoding="utf-8")
    tests = repository / "tests"
    tests.mkdir()
    (tests / "test_smoke.py").write_text(
        "def test_real_resume():\n    assert 2 + 2 == 4\n", encoding="utf-8"
    )
    subprocess.run(["git", "init", "-q", str(repository)], check=True)

    state = tmp_path / "toolhub-state"
    toolhub_state = state / "toolhub"
    monkeypatch.setenv(TOOLHUB_PROJECT_ENV, str(toolhub.resolve()))
    monkeypatch.setenv("TOOLHUB_STATE_ROOT", str(toolhub_state))
    monkeypatch.setenv("REPO_DOCTOR_STATE_ROOT", str(state / "repo-doctor-state"))

    monkeypatch.chdir(repository)
    runner = CliRunner()
    scan_response = runner.invoke(app, ["scan", ".", "--tool-backend", "mcp"])
    assert scan_response.exit_code == 0, scan_response.output
    assert "Approval required" in scan_response.output
    session_files = list((state / "repo-doctor-state" / "sessions").glob("*.json"))
    assert len(session_files) == 1
    assert not (repository / ".repo-doctor").exists()
    session = load_session_file(session_files[0])
    request_id = session.operations[0].request_id

    admin_env = os.environ.copy()
    admin_env["TOOLHUB_WORKSPACE_ROOT"] = str(repository.resolve())
    subprocess.run(
        [str(admin), "approve", request_id],
        cwd=toolhub,
        env=admin_env,
        input="APPROVE\n",
        capture_output=True,
        text=True,
        check=True,
    )

    resume_response = runner.invoke(app, ["resume", session.session_id])
    assert resume_response.exit_code == 0, resume_response.output
    assert "Python tests: PASS" in resume_response.output
    assert "1 passed" in resume_response.output
    assert "All pending verification completed" in resume_response.output
    with MCPToolBackend(repository, toolhub_project=toolhub) as backend:
        status = backend.request_status(request_id)
    assert status.outcome.value == "APPROVAL_CONSUMED"

    repeated = runner.invoke(app, ["resume", session.session_id])
    assert repeated.exit_code == 0, repeated.output
    assert not any(thread.name == "repo-doctor-mcp" for thread in threading.enumerate())
