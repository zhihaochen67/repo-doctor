"""Root-bound local and MCP tool execution backends."""

from __future__ import annotations

import asyncio
import hashlib
import os
import queue
import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, Protocol, Self

from .models import (
    CommandResult,
    FileReadResult,
    GitDiffResult,
    GitStatusEntry,
    GitStatusResult,
    PatchMutationResult,
)
from .runner import run_command as run_local_command
from .security import verification_environment
from .toolhub_contract import (
    CAPABILITIES_TOOL,
    REQUEST_STATUS_TOOL,
    ContractOutcome,
    ContractResponse,
    ContractValidationError,
    RequestStatusResult,
    ToolHubCapabilities,
    expected_resume_tool,
    parse_capabilities,
    parse_contract_response,
    parse_request_status,
)

TOOLHUB_PROJECT_ENV = "REPO_DOCTOR_TOOLHUB_PROJECT"
DEFAULT_WINDOWS_TOOLHUB_PROJECT = Path(r"D:\mcp-toolhub")
MCP_CLEANUP_TIMEOUT_SECONDS = 10.0
_PYTHON_BOOTSTRAP_ENVIRONMENT = {
    "PYTHONBREAKPOINT",
    "PYTHONCASEOK",
    "PYTHONEXECUTABLE",
    "PYTHONHOME",
    "PYTHONINSPECT",
    "PYTHONNOUSERSITE",
    "PYTHONPATH",
    "PYTHONPLATLIBDIR",
    "PYTHONPYCACHEPREFIX",
    "PYTHONSAFEPATH",
    "PYTHONSTARTUP",
    "PYTHONUSERBASE",
    "PYTHONWARNINGS",
}


class ToolBackendError(Exception):
    """Base class for actionable tool backend failures."""


class ToolBackendStartupError(ToolBackendError):
    """A tool backend could not initialize."""


class ToolCallError(ToolBackendError):
    """A backend tool call failed or returned an invalid result."""


class FileReadError(ToolCallError):
    """A text file selected by Repo Doctor could not be read."""


class MutationConflictError(ToolCallError):
    """ToolHub refused a mutation because its optimistic hash was stale."""

    def __init__(
        self,
        message: str,
        *,
        trace_id: str | None = None,
        error_code: str | None = None,
    ) -> None:
        super().__init__(message)
        self.trace_id = trace_id
        self.error_code = error_code


class ToolBackendKind(StrEnum):
    """CLI-selectable execution backends."""

    LOCAL = "local"
    MCP = "mcp"


class ToolBackend(Protocol):
    """Operations currently needed from Repo Doctor execution backends."""

    root: Path
    verification_in_place: bool

    def __enter__(self) -> Self: ...

    def __exit__(self, *exc_info: object) -> None: ...

    def read_file(self, path: str) -> FileReadResult: ...

    def run_command(
        self,
        name: str,
        command: tuple[str, ...],
        cwd: str = ".",
        timeout: int = 120,
    ) -> CommandResult: ...

    def git_status(self) -> GitStatusResult: ...

    def git_diff(self, path: str | None = None, staged: bool = False) -> GitDiffResult: ...

    def close(self) -> None: ...


def _canonical_repository(root: Path) -> Path:
    try:
        resolved = root.expanduser().resolve(strict=True)
    except OSError as error:
        raise ToolBackendStartupError(f"Repository path does not exist: {root}") from error
    if not resolved.is_dir():
        raise ToolBackendStartupError(f"Repository path is not a directory: {resolved}")
    return resolved


def _relative_path(value: str, *, label: str = "path") -> str:
    if not value or "\x00" in value:
        raise ToolCallError(f"Backend {label} must be a non-empty relative path.")
    if PureWindowsPath(value).is_absolute() or PurePosixPath(value).is_absolute():
        raise ToolCallError(f"Backend {label} must be relative to the configured repository.")
    normalized = value.replace("\\", "/")
    parts = normalized.split("/")
    if any(part in {"", ".."} for part in parts):
        raise ToolCallError(f"Backend {label} cannot traverse outside the configured repository.")
    return PurePosixPath(*(part for part in parts if part != ".")).as_posix() or "."


def _resolve_local(root: Path, value: str) -> Path:
    relative = _relative_path(value)
    target = root.joinpath(*PurePosixPath(relative).parts).resolve()
    if not target.is_relative_to(root):
        raise ToolCallError("Backend path escapes the configured repository.")
    return target


class LocalToolBackend:
    """Adapter preserving Repo Doctor's existing local execution behavior."""

    verification_in_place = False

    def __init__(self, root: Path):
        self.root = _canonical_repository(root)

    def __enter__(self) -> Self:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def close(self) -> None:
        """The local backend owns no persistent resources."""

    def read_file(self, path: str) -> FileReadResult:
        relative = _relative_path(path)
        target = _resolve_local(self.root, relative)
        try:
            data = target.read_bytes()
            content = data.decode("utf-8")
        except (OSError, UnicodeError) as error:
            raise FileReadError(
                f"Could not read repository file '{relative}' locally: {error}"
            ) from error
        return FileReadResult(
            relative,
            len(data),
            hashlib.sha256(data).hexdigest(),
            content,
        )

    def run_command(
        self,
        name: str,
        command: tuple[str, ...],
        cwd: str = ".",
        timeout: int = 120,
    ) -> CommandResult:
        if not command:
            raise ToolCallError("Backend command cannot be empty.")
        working_directory = _resolve_local(self.root, cwd)
        if not working_directory.is_dir():
            raise ToolCallError(f"Backend working directory is not a directory: {cwd}")
        return run_local_command(name, command, working_directory, timeout)

    def git_status(self) -> GitStatusResult:
        completed = self._git("status", "--porcelain=v1", "--branch")
        branch, entries = _parse_git_status(completed.stdout)
        return GitStatusResult(".", branch, not entries, entries, completed.stdout)

    def git_diff(self, path: str | None = None, staged: bool = False) -> GitDiffResult:
        arguments = ["diff", "--no-ext-diff", "--no-textconv"]
        if staged:
            arguments.append("--cached")
        normalized_path = None
        if path is not None:
            normalized_path = _relative_path(path)
            arguments.extend(("--", normalized_path))
        completed = self._git(*arguments)
        additions, deletions, binary = _count_git_diff(completed.stdout)
        return GitDiffResult(
            normalized_path,
            staged,
            additions,
            deletions,
            binary,
            completed.stdout,
        )

    def _git(self, *arguments: str) -> subprocess.CompletedProcess[str]:
        try:
            completed = subprocess.run(
                ["git", *arguments],
                cwd=self.root,
                env=verification_environment(),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=20,
                shell=False,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ToolCallError(f"Local Git operation failed: {error}") from error
        if completed.returncode:
            detail = completed.stderr.strip() or "git failed"
            raise ToolCallError(f"Local Git operation failed: {detail}")
        return completed


@dataclass(frozen=True)
class MCPServerProcess:
    """Complete stdio launch configuration for ToolHub."""

    command: str
    args: tuple[str, ...]
    cwd: Path
    env: dict[str, str]


class MCPClient(Protocol):
    """Transport seam used by MCPToolBackend and unit-test fakes."""

    def start(self) -> None: ...

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]: ...

    def close(self) -> None: ...


@dataclass
class _WorkerRequest:
    name: str | None
    arguments: dict[str, Any]
    response: queue.Queue[object]


class _StdioMCPClient:
    """Persistent official MCP client session hosted by one worker task."""

    def __init__(self, process: MCPServerProcess):
        self.process = process
        self._requests: queue.Queue[_WorkerRequest] = queue.Queue()
        self._startup: queue.Queue[object] = queue.Queue(maxsize=1)
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(
            target=self._thread_main,
            name="repo-doctor-mcp",
            daemon=True,
        )
        self._thread.start()
        outcome = self._startup.get(timeout=MCP_CLEANUP_TIMEOUT_SECONDS)
        if isinstance(outcome, BaseException):
            self._thread.join(timeout=MCP_CLEANUP_TIMEOUT_SECONDS)
            raise outcome

    def call_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        if self._thread is None or not self._thread.is_alive():
            raise RuntimeError("MCP client session is not running")
        response: queue.Queue[object] = queue.Queue(maxsize=1)
        self._requests.put(_WorkerRequest(name, dict(arguments), response))
        outcome = response.get()
        if isinstance(outcome, BaseException):
            raise outcome
        if not isinstance(outcome, dict):
            raise RuntimeError("MCP tool returned an unexpected result")
        return outcome

    def close(self) -> None:
        thread = self._thread
        if thread is None:
            return
        if thread.is_alive():
            self._requests.put(_WorkerRequest(None, {}, queue.Queue(maxsize=1)))
            thread.join(timeout=MCP_CLEANUP_TIMEOUT_SECONDS)
        self._thread = None
        if thread.is_alive():
            raise RuntimeError("MCP ToolHub subprocess did not shut down cleanly")

    def _thread_main(self) -> None:
        try:
            asyncio.run(self._run())
        except BaseException as error:
            if self._startup.empty():
                self._startup.put(error)

    async def _run(self) -> None:
        try:
            from mcp import ClientSession, StdioServerParameters
            from mcp.client.stdio import stdio_client
        except ImportError as error:
            raise RuntimeError(
                "MCP backend requires the 'mcp' Python package; reinstall Repo Doctor."
            ) from error

        parameters = StdioServerParameters(
            command=self.process.command,
            args=list(self.process.args),
            cwd=self.process.cwd,
            env=self.process.env,
        )
        async with stdio_client(parameters) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                self._startup.put(None)
                while True:
                    request = await asyncio.to_thread(self._requests.get)
                    if request.name is None:
                        break
                    try:
                        result = await session.call_tool(request.name, request.arguments)
                        request.response.put(_tool_payload(result))
                    except BaseException as error:
                        request.response.put(error)


def _tool_payload(result: Any) -> dict[str, Any]:
    if getattr(result, "is_error", False):
        detail = _tool_text(result) or "ToolHub reported an MCP tool error."
        raise RuntimeError(detail)
    structured = getattr(result, "structured_content", None)
    if isinstance(structured, dict):
        return structured
    detail = _tool_text(result)
    suffix = f" Diagnostic text: {detail[:500]}" if detail else ""
    raise RuntimeError(
        "ToolHub returned no structuredContent object; Contract V1 does not permit "
        f"JSON-text lifecycle fallback.{suffix}"
    )


def _tool_text(result: Any) -> str:
    return "\n".join(
        item.text
        for item in getattr(result, "content", ())
        if getattr(item, "type", None) == "text" and isinstance(getattr(item, "text", None), str)
    )


def _configured_toolhub_project(toolhub_project: Path | None) -> Path:
    """Resolve one explicit ToolHub checkout without global discovery."""
    if toolhub_project is not None:
        candidate = Path(toolhub_project)
        source = "Configured ToolHub project"
    elif TOOLHUB_PROJECT_ENV in os.environ:
        candidate = Path(os.environ[TOOLHUB_PROJECT_ENV])
        source = TOOLHUB_PROJECT_ENV
    elif os.name == "nt" and DEFAULT_WINDOWS_TOOLHUB_PROJECT.is_dir():
        candidate = DEFAULT_WINDOWS_TOOLHUB_PROJECT
        source = "Windows ToolHub default"
    else:
        raise ToolBackendStartupError(
            f"ToolHub project is not configured. Set {TOOLHUB_PROJECT_ENV} to the absolute "
            "path of a production ToolHub checkout containing a project-local .venv."
        )
    if not candidate.is_absolute():
        raise ToolBackendStartupError(f"{source} must be an absolute path, got {str(candidate)!r}.")
    try:
        project = candidate.resolve(strict=True)
    except (OSError, RuntimeError) as error:
        raise ToolBackendStartupError(
            f"{source} does not exist: {candidate}. Set {TOOLHUB_PROJECT_ENV} to a valid "
            "production ToolHub checkout."
        ) from error
    if not project.is_dir():
        raise ToolBackendStartupError(f"{source} is not a directory: {project}")
    return project


def _toolhub_environment(root: Path) -> dict[str, str]:
    """Build a credential-safe environment without Python import-path injection."""
    environment = verification_environment()
    for name in list(environment):
        if name.upper() in _PYTHON_BOOTSTRAP_ENVIRONMENT:
            environment.pop(name)
    environment["TOOLHUB_WORKSPACE_ROOT"] = str(root)
    return environment


def _toolhub_process(
    root: Path,
    toolhub_project: Path | None = None,
    *,
    platform_name: str | None = None,
) -> MCPServerProcess:
    project = _configured_toolhub_project(toolhub_project)
    workspace = _canonical_repository(root)
    platform = platform_name or os.name

    if platform == "nt":
        bundled_python = project / ".venv" / "Scripts" / "python.exe"
    else:
        bundled_python = project / ".venv" / "bin" / "python"
    if not bundled_python.is_file():
        raise ToolBackendStartupError(
            f"Configured ToolHub checkout has no project-local Python interpreter at "
            f"{bundled_python}. Create the checkout's .venv or set {TOOLHUB_PROJECT_ENV} "
            "to a prepared production checkout; Repo Doctor will not use PATH/global fallbacks."
        )
    return MCPServerProcess(
        command=str(bundled_python),
        args=("-m", "mcp_toolhub", "serve"),
        cwd=project,
        env=_toolhub_environment(workspace),
    )


class MCPToolBackend:
    """Root-bound Repo Doctor adapter for MCP ToolHub over stdio."""

    verification_in_place = True

    def __init__(
        self,
        root: Path,
        *,
        toolhub_project: Path | None = None,
        client_factory: Callable[[MCPServerProcess], MCPClient] = _StdioMCPClient,
    ):
        self.root = _canonical_repository(root)
        self.server_process = _toolhub_process(self.root, toolhub_project)
        self._client = client_factory(self.server_process)
        self._started = False
        self.capabilities: ToolHubCapabilities | None = None

    def __enter__(self) -> Self:
        self._start()
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()

    def _start(self) -> None:
        if self._started:
            return
        try:
            self._client.start()
            payload = self._client.call_tool(CAPABILITIES_TOOL, {})
            self.capabilities = parse_capabilities(payload)
        except Exception as error:
            try:
                self._client.close()
            except Exception:
                pass
            raise ToolBackendStartupError(
                "Could not start MCP ToolHub with a compatible Contract V1 backend: "
                f"{error}. Verify the production 'mcp-toolhub serve' environment and "
                "toolhub.capabilities response."
            ) from error
        self._started = True

    def close(self) -> None:
        try:
            self._client.close()
        except Exception as error:
            raise ToolBackendError(f"Could not cleanly stop MCP ToolHub: {error}") from error
        finally:
            self._started = False
            self.capabilities = None

    def _call(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        self._start()
        try:
            return self._client.call_tool(name, arguments)
        except ToolBackendError:
            raise
        except Exception as error:
            raise ToolCallError(f"ToolHub call {name} failed: {error}") from error

    def _contract_call(
        self,
        name: str,
        arguments: dict[str, Any],
        *,
        initial_tool: str | None = None,
    ) -> ContractResponse:
        payload = self._call(name, arguments)
        try:
            response = parse_contract_response(payload, call=name)
            if response.approval is not None:
                capabilities = self.capabilities
                if capabilities is None:
                    raise ContractValidationError("ToolHub capabilities were not negotiated.")
                if initial_tool is None:
                    if response.approval.resume_tool not in capabilities.allowed_resume_tools:
                        raise ContractValidationError(
                            "ToolHub returned an approval handle with an undeclared resume_tool."
                        )
                else:
                    expected = capabilities.resume_tool_for(initial_tool)
                    if response.approval.resume_tool != expected:
                        raise ContractValidationError(
                            f"Unsafe resume_tool for {initial_tool}: expected {expected!r}, "
                            f"got {response.approval.resume_tool!r}."
                        )
        except ContractValidationError as error:
            raise ToolCallError(f"ToolHub call {name} violated Contract V1: {error}") from error
        return response

    def request_status(self, request_id: str) -> RequestStatusResult:
        """Return fresh server-owned approval state without granting local authority."""
        request_id = _approval_request_id(request_id)
        payload = self._call(REQUEST_STATUS_TOOL, {"request_id": request_id})
        try:
            status = parse_request_status(payload, request_id=request_id)
            if status.approval is not None:
                capabilities = self.capabilities
                if capabilities is None:
                    raise ContractValidationError("ToolHub capabilities were not negotiated.")
                if status.approval.resume_tool not in capabilities.allowed_resume_tools:
                    raise ContractValidationError(
                        "ToolHub status returned an undeclared resume_tool."
                    )
        except ContractValidationError as error:
            raise ToolCallError(
                f"ToolHub call {REQUEST_STATUS_TOOL} violated Contract V1: {error}"
            ) from error
        return status

    def read_file(self, path: str) -> FileReadResult:
        relative = _relative_path(path)
        try:
            self._start()
        except ToolBackendStartupError as error:
            raise ToolBackendStartupError(
                f"{error} (while preparing to read '{relative}')"
            ) from error
        try:
            payload = self._call("filesystem.read_file", {"path": relative})
        except ToolCallError as error:
            raise FileReadError(
                f"Could not read repository file '{relative}' via MCP ToolHub: {error}"
            ) from error
        try:
            return FileReadResult(
                path=str(payload["path"]),
                size=int(payload["size"]),
                sha256=str(payload["sha256"]),
                content=str(payload["content"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise FileReadError(
                f"ToolHub returned an invalid filesystem.read_file result for '{relative}'."
            ) from error

    def run_command(
        self,
        name: str,
        command: tuple[str, ...],
        cwd: str = ".",
        timeout: int = 120,
    ) -> CommandResult:
        if not command:
            raise ToolCallError("Backend command cannot be empty.")
        relative_cwd = _relative_path(cwd, label="working directory")
        started = time.monotonic()
        response = self._contract_call(
            "shell.run",
            {
                "program": command[0],
                "args": list(command[1:]),
                "cwd": relative_cwd,
                "timeout_seconds": timeout,
            },
            initial_tool="shell.run",
        )
        return _shell_command_result(response, name, command, started)

    def run_approved(
        self,
        request_id: str,
        *,
        name: str = "Verification",
        resume_tool: str | None = None,
    ) -> CommandResult:
        """Ask ToolHub to execute one already-approved, immutable shell request."""
        request_id = _approval_request_id(request_id)
        approved_tool = self._validated_resume_tool("shell.run", resume_tool)
        started = time.monotonic()
        response = self._contract_call(
            approved_tool,
            {"request_id": request_id},
            initial_tool="shell.run",
        )
        return _shell_command_result(
            response,
            name,
            (),
            started,
            fallback_request_id=request_id,
        )

    def apply_patch(
        self,
        path: str,
        patch: str,
        expected_hash: str,
    ) -> PatchMutationResult:
        """Submit one validated patch with mandatory optimistic concurrency."""
        relative = _relative_path(path)
        _sha256(expected_hash)
        if not patch or "\x00" in patch:
            raise ToolCallError("Backend patch must be non-empty text without null bytes.")
        response = self._contract_call(
            "filesystem.apply_patch",
            {
                "path": relative,
                "patch": patch,
                "expected_hash": expected_hash,
            },
            initial_tool="filesystem.apply_patch",
        )
        return _patch_mutation_result(response, fallback_path=relative)

    def run_approved_mutation(
        self,
        request_id: str,
        *,
        resume_tool: str | None = None,
        expected_path: str,
        expected_trace_id: str,
    ) -> PatchMutationResult:
        """Execute only the immutable mutation snapshot stored by ToolHub."""
        request_id = _approval_request_id(request_id)
        expected_path = _relative_path(expected_path)
        expected_trace_id = _lifecycle_trace_id(expected_trace_id)
        approved_tool = self._validated_resume_tool("filesystem.apply_patch", resume_tool)
        response = self._contract_call(
            approved_tool,
            {"request_id": request_id},
            initial_tool="filesystem.apply_patch",
        )
        return _patch_mutation_result(
            response,
            fallback_path=expected_path,
            fallback_request_id=request_id,
            expected_trace_id=expected_trace_id,
        )

    def _validated_resume_tool(self, initial_tool: str, declared: str | None) -> str:
        capabilities = self.capabilities
        if capabilities is None:
            self._start()
            capabilities = self.capabilities
        if capabilities is None:  # pragma: no cover - defensive after successful startup
            raise ToolCallError("ToolHub capabilities were not negotiated.")
        expected = expected_resume_tool(initial_tool)
        negotiated = capabilities.resume_tool_for(initial_tool)
        if negotiated != expected:
            raise ToolCallError(f"Unsafe negotiated resume tool for {initial_tool}.")
        if declared is not None and declared != expected:
            raise ToolCallError(f"Refusing unexpected resume_tool {declared!r} for {initial_tool}.")
        return negotiated

    def git_status(self) -> GitStatusResult:
        payload = self._call("git.status", {})
        try:
            entries = tuple(
                GitStatusEntry(code=str(item["code"]), path=str(item["path"]))
                for item in payload["entries"]
            )
            return GitStatusResult(
                path=str(payload["path"]),
                branch=payload.get("branch"),
                clean=bool(payload["clean"]),
                entries=entries,
                raw=str(payload["raw"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ToolCallError("ToolHub returned an invalid git.status result.") from error

    def git_diff(self, path: str | None = None, staged: bool = False) -> GitDiffResult:
        normalized_path = _relative_path(path) if path is not None else None
        payload = self._call("git.diff", {"path": normalized_path, "staged": staged})
        try:
            return GitDiffResult(
                path=payload.get("path"),
                staged=bool(payload["staged"]),
                additions=payload.get("additions"),
                deletions=payload.get("deletions"),
                binary=bool(payload["binary"]),
                raw=str(payload["raw"]),
            )
        except (KeyError, TypeError, ValueError) as error:
            raise ToolCallError("ToolHub returned an invalid git.diff result.") from error


def _shell_command_result(
    response: ContractResponse,
    name: str,
    fallback_command: tuple[str, ...],
    started: float,
    *,
    fallback_request_id: str | None = None,
) -> CommandResult:
    """Validate and map a ToolHub shell response into Repo Doctor's model."""
    try:
        payload = response.payload
        if response.outcome is ContractOutcome.CONFLICT:
            raise TypeError("shell.run cannot return CONFLICT")
        executed = payload["executed"]
        if not isinstance(executed, bool):
            raise TypeError("executed must be a boolean")
        should_execute = response.outcome in {
            ContractOutcome.SUCCEEDED,
            ContractOutcome.COMMAND_FAILED,
            ContractOutcome.TIMED_OUT,
        }
        if executed is not should_execute:
            raise TypeError("executed contradicts outcome")
        timed_out = payload["timed_out"]
        if not isinstance(timed_out, bool):
            raise TypeError("timed_out must be a boolean")
        if timed_out is not (response.outcome is ContractOutcome.TIMED_OUT):
            raise TypeError("timed_out contradicts outcome")
        program = payload.get("program", "")
        arguments = payload.get("args", [])
        if (
            not isinstance(program, str)
            or not isinstance(arguments, list)
            or not all(isinstance(item, str) for item in arguments)
        ):
            raise TypeError("program and args must describe a command")
        command = (program, *arguments) if program else fallback_command
        if executed:
            returncode = payload.get("returncode")
            if returncode is None and response.outcome is ContractOutcome.TIMED_OUT:
                exit_code = 124
            else:
                exit_code = int(returncode)
            if response.outcome is ContractOutcome.SUCCEEDED and exit_code != 0:
                raise TypeError("SUCCEEDED must have returncode 0")
            if response.outcome is ContractOutcome.COMMAND_FAILED and exit_code == 0:
                raise TypeError("COMMAND_FAILED must have a nonzero returncode")
        else:
            if payload.get("returncode") is not None:
                raise TypeError("non-executed shell result cannot have a returncode")
            exit_code = 126
        request_id, approval_status, expires_at, resume_tool = _response_approval_metadata(
            response,
            fallback_request_id=fallback_request_id,
        )
        error_code = response.error.code if response.error else None
        error_retryable = response.error.retryable if response.error else None
        diagnostic = response.message or (response.error.message if response.error else "")
        return CommandResult(
            name=name,
            command=command,
            exit_code=exit_code,
            stdout=str(payload.get("stdout", "")),
            stderr=str(payload.get("stderr", "")),
            duration=time.monotonic() - started,
            timed_out=timed_out,
            approval_required=response.outcome is ContractOutcome.APPROVAL_REQUIRED,
            request_id=request_id,
            approval_status=approval_status,
            message=diagnostic,
            executed=executed,
            trace_id=response.trace_id,
            toolhub_outcome=response.outcome.value,
            resume_tool=resume_tool,
            expires_at=expires_at,
            error_code=error_code,
            error_retryable=error_retryable,
        )
    except (KeyError, TypeError, ValueError, ContractValidationError) as error:
        raise ToolCallError("ToolHub returned an invalid shell result.") from error


def _response_approval_metadata(
    response: ContractResponse,
    *,
    fallback_request_id: str | None = None,
) -> tuple[str | None, str | None, str | None, str | None]:
    approval = response.approval
    request_id = approval.request_id if approval else fallback_request_id
    approval_status = approval.status.value if approval else None
    expires_at = approval.expires_at if approval else None
    resume_tool = approval.resume_tool if approval else None

    payload_request_id = response.payload.get("request_id")
    if payload_request_id is not None:
        payload_request_id = _approval_request_id(payload_request_id)
        if request_id is not None and payload_request_id != request_id:
            raise ContractValidationError("Top-level request_id contradicts the approval handle.")
        request_id = payload_request_id
    if fallback_request_id is not None and request_id != fallback_request_id:
        raise ContractValidationError("ToolHub returned a different approval request ID.")

    payload_status = response.payload.get("approval_status")
    if payload_status is not None:
        if not isinstance(payload_status, str) or payload_status != approval_status:
            raise ContractValidationError(
                "Top-level approval_status contradicts the approval handle."
            )
    return request_id, approval_status, expires_at, resume_tool


def _approval_request_id(request_id: str) -> str:
    if (
        not isinstance(request_id, str)
        or not request_id
        or len(request_id) > 512
        or any(ord(character) < 32 for character in request_id)
    ):
        raise ToolCallError("ToolHub approval request ID must be non-empty bounded text.")
    return request_id


def _lifecycle_trace_id(trace_id: str) -> str:
    if (
        not isinstance(trace_id, str)
        or not trace_id
        or len(trace_id) > 512
        or any(ord(character) < 32 for character in trace_id)
    ):
        raise ToolCallError("ToolHub lifecycle trace ID must be non-empty bounded text.")
    return trace_id


def _sha256(value: str) -> str:
    if len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise ToolCallError("Expected hash must be a lowercase SHA-256 digest.")
    return value


def _patch_mutation_result(
    response: ContractResponse,
    *,
    fallback_path: str,
    fallback_request_id: str | None = None,
    expected_trace_id: str | None = None,
) -> PatchMutationResult:
    """Validate and map a ToolHub filesystem mutation response."""
    try:
        payload = response.payload
        if response.outcome in {ContractOutcome.COMMAND_FAILED, ContractOutcome.TIMED_OUT}:
            raise TypeError("filesystem.apply_patch returned a shell-only outcome")
        executed = payload["executed"]
        if not isinstance(executed, bool):
            raise TypeError("executed must be a boolean")
        if executed is not (response.outcome is ContractOutcome.SUCCEEDED):
            raise TypeError("executed contradicts outcome")
        changed = payload.get("changed", False)
        if not isinstance(changed, bool):
            raise TypeError("changed must be a boolean")
        path = payload["path"]
        if not isinstance(path, str):
            raise TypeError("path must be text")
        if fallback_path and path != fallback_path:
            raise TypeError("path contradicts submitted patch target")
        request_id, approval_status, expires_at, resume_tool = _response_approval_metadata(
            response,
            fallback_request_id=fallback_request_id,
        )
        if expected_trace_id is not None and response.trace_id != expected_trace_id:
            raise ContractValidationError(
                "ToolHub patch result returned a different lifecycle trace_id."
            )
        previous_hash = payload.get("previous_hash")
        new_hash = payload.get("new_hash")
        if previous_hash is not None:
            _sha256(str(previous_hash))
        if new_hash is not None:
            _sha256(str(new_hash))
        if not executed and changed:
            raise TypeError("non-executed patch result cannot report changed=true")
        if response.outcome is ContractOutcome.CONFLICT:
            if (
                response.error is None
                or response.error.retryable
                or response.error.code not in {"MUTATION_CONFLICT", "EXPECTED_HASH_MISMATCH"}
            ):
                raise ContractValidationError(
                    "CONFLICT requires a non-retryable structured mutation-conflict error."
                )
            raise MutationConflictError(
                response.error.message,
                trace_id=response.trace_id,
                error_code=response.error.code,
            )
        return PatchMutationResult(
            path=path or fallback_path,
            executed=executed,
            changed=changed,
            additions=int(payload.get("additions", 0)),
            deletions=int(payload.get("deletions", 0)),
            bytes_before=int(payload.get("bytes_before", 0)),
            bytes_after=int(payload.get("bytes_after", 0)),
            previous_hash=str(previous_hash) if previous_hash is not None else None,
            new_hash=str(new_hash) if new_hash is not None else None,
            trace_id=response.trace_id,
            request_id=request_id,
            approval_status=approval_status,
            message=response.message or (response.error.message if response.error else ""),
            toolhub_outcome=response.outcome.value,
            resume_tool=resume_tool,
            expires_at=expires_at,
            error_code=response.error.code if response.error else None,
            error_retryable=response.error.retryable if response.error else None,
        )
    except MutationConflictError:
        raise
    except (KeyError, TypeError, ValueError, ContractValidationError) as error:
        raise ToolCallError("ToolHub returned an invalid filesystem patch result.") from error


def create_tool_backend(kind: ToolBackendKind, root: Path) -> ToolBackend:
    """Create the selected root-bound backend; local remains the default in CLI callers."""

    if kind is ToolBackendKind.LOCAL:
        return LocalToolBackend(root)
    if kind is ToolBackendKind.MCP:
        return MCPToolBackend(root)
    raise ToolBackendStartupError(f"Unsupported tool backend: {kind}")


def _parse_git_status(raw: str) -> tuple[str | None, tuple[GitStatusEntry, ...]]:
    branch = None
    entries: list[GitStatusEntry] = []
    for line in raw.splitlines():
        if line.startswith("## "):
            branch = line[3:].split("...", 1)[0].split(" [", 1)[0].strip()
        elif len(line) >= 3:
            entries.append(GitStatusEntry(line[:2], line[3:].strip()))
    return branch, tuple(entries)


def _count_git_diff(raw: str) -> tuple[int | None, int | None, bool]:
    if "Binary files" in raw:
        return None, None, True
    additions = sum(
        1 for line in raw.splitlines() if line.startswith("+") and not line.startswith("+++")
    )
    deletions = sum(
        1 for line in raw.splitlines() if line.startswith("-") and not line.startswith("---")
    )
    return additions, deletions, False
