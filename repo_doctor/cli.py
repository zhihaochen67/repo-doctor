"""Command-line interface for Repo Doctor."""

from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console

from .ai.errors import AIError
from .ai.fixer import execute_ai_fix
from .ai.mcp_fixer import execute_mcp_ai_fix
from .ai.prompts import DEFAULT_PROMPT_VARIANT, prompt_profile
from .ai.provider import provider_from_env
from .ai.workflow import analyze_repository
from .backends import ToolBackendError, ToolBackendKind, create_tool_backend
from .fixer import apply_high_confidence_fix, verify_clean_git
from .repair_sessions import (
    RepairOperationKind,
    RepairPhase,
    RepairSession,
    is_repair_session,
    load_repair_session,
    render_repair_session,
    resume_repair_session,
)
from .report import render_report
from .scanner import scan
from .sessions import (
    ScanSession,
    SessionStatus,
    create_scan_session,
    load_session,
    resume_scan_session,
    save_session,
)

app = typer.Typer(help="Diagnose and repair a local repository.", no_args_is_help=True)
console = Console()
MAX_TASK_FILE_BYTES = 64_000


@app.command("scan")
def scan_command(
    repository_path: Path,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
    timeout: int = 120,
    ai: Annotated[bool, typer.Option("--ai", help="Enable configured semantic analysis.")] = False,
    tool_backend: Annotated[
        ToolBackendKind,
        typer.Option("--tool-backend", help="Tool execution backend: local or mcp."),
    ] = ToolBackendKind.LOCAL,
    trusted_execution: Annotated[
        bool,
        typer.Option(
            "--trusted-execution",
            help=(
                "Run discovered repository commands as the current user; commands are NOT "
                "sandboxed."
            ),
        ),
    ] = False,
) -> None:
    """Statically scan REPOSITORY_PATH; optionally run trusted host verification."""
    try:
        session = None
        with console.status("[cyan]Examining repository…"):
            if tool_backend is ToolBackendKind.LOCAL:
                result = scan(repository_path, timeout, verify=trusted_execution)
            else:
                backend = create_tool_backend(tool_backend, repository_path)
                result = scan(
                    repository_path,
                    timeout,
                    backend=backend,
                    verify=trusted_execution,
                )
            if ai:
                result.ai_requested = True
                try:
                    analyze_repository(result, provider_from_env())
                except AIError as error:
                    result.ai_error = str(error)
            if tool_backend is ToolBackendKind.MCP and any(
                item.approval_required for item in result.commands
            ):
                session = create_scan_session(result)
                save_session(session)
        report = render_report(result)
        if output:
            output.write_text(report, encoding="utf-8")
            console.print(f"[green]Report written to {output}[/green]")
        else:
            console.print(report)
        console.print(f"[bold]Health score: {result.score}/100[/bold]")
        if session is not None:
            _print_approval_instructions(session)
    except (OSError, ToolBackendError, ValueError) as error:
        console.print(f"[red]Error: {error}[/red]")
        raise typer.Exit(2) from error


@app.command("resume")
def resume_command(
    session_id: str,
    output: Annotated[Path | None, typer.Option("--output", "-o")] = None,
) -> None:
    """Resume pending ToolHub scan or AI repair requests."""
    try:
        if is_repair_session(session_id):
            repair = load_repair_session(session_id)
            with console.status("[cyan]Checking ToolHub repair approvals…"):
                resume_repair_session(repair)
            report = render_repair_session(repair)
            if output:
                output.write_text(report, encoding="utf-8")
                console.print(f"[green]Report written to {output}[/green]")
            else:
                console.print(report)
            if repair.pending_operations:
                _print_repair_approval_instructions(repair)
            elif repair.phase is RepairPhase.VERIFIED_PASS:
                console.print("[green]Repair verification passed.[/green]")
            else:
                console.print(
                    f"[yellow]Repair stopped in state {repair.phase.value.upper()}.[/yellow]"
                )
            return
        session = load_session(session_id)
        with console.status("[cyan]Checking ToolHub approvals…"):
            resume_scan_session(session)
        report = render_report(session.result)
        if output:
            output.write_text(report, encoding="utf-8")
            console.print(f"[green]Report written to {output}[/green]")
        else:
            console.print(report)
        console.print(f"[bold]Health score: {session.result.score}/100[/bold]")
        if session.pending_operations:
            console.print("[yellow]Partial completion; approvals are still required.[/yellow]")
            _print_approval_instructions(session)
        elif session.status is SessionStatus.COMPLETED:
            console.print("[green]All pending verification completed.[/green]")
        else:
            console.print(
                "[yellow]Verification could not continue for one or more requests. "
                "See the report for ToolHub states.[/yellow]"
            )
    except (OSError, ToolBackendError, ValueError) as error:
        console.print(f"[red]Error: {error}[/red]")
        raise typer.Exit(2) from error


def _print_approval_instructions(session: ScanSession) -> None:
    console.print("\n[yellow]Approval required.[/yellow]")
    console.print("\nSession:")
    console.print(f"  {session.session_id}", markup=False)
    for operation in session.pending_operations:
        console.print(f"\n{operation.name}:", markup=False)
        console.print(f"  request_id: {operation.request_id}", markup=False)
    console.print("\nApprove the required requests with ToolHub's trusted admin CLI:")
    console.print("  mcp-toolhub-admin list", markup=False)
    console.print("  mcp-toolhub-admin approve <request_id>", markup=False)
    console.print(f"\nThen run from {session.target_repository}:", markup=False)
    console.print(f"  repo-doctor resume {session.session_id}", markup=False)


def _print_repair_approval_instructions(session: RepairSession) -> None:
    patch_pending = any(
        item.kind is RepairOperationKind.PATCH for item in session.pending_operations
    )
    heading = "Patch approval required." if patch_pending else "Verification approval required."
    console.print(f"\n[yellow]{heading}[/yellow]")
    console.print("\nSession:")
    console.print(f"  {session.session_id}", markup=False)
    console.print("\nFinding:")
    console.print(f"  {session.finding_id} - {session.finding_title}", markup=False)
    console.print("\nFile:")
    console.print(f"  {session.target_file}", markup=False)
    for operation in session.pending_operations:
        console.print(f"\n{operation.name}:", markup=False)
        console.print(f"  Request: {operation.request_id}", markup=False)
    console.print("\nApprove with ToolHub's trusted admin CLI:")
    console.print("  mcp-toolhub-admin list", markup=False)
    console.print("  mcp-toolhub-admin approve <request_id>", markup=False)
    console.print("\nResume:")
    console.print(f"  repo-doctor resume {session.session_id}", markup=False)


def _repair_task(task: str | None, task_file: Path | None) -> str | None:
    if task is not None and task_file is not None:
        raise ValueError("Use either --task or --task-file, not both.")
    if task_file is None:
        return task
    try:
        payload = task_file.read_bytes()
    except OSError as error:
        raise ValueError(f"Could not read task file: {task_file}.") from error
    if len(payload) > MAX_TASK_FILE_BYTES:
        raise ValueError(f"Task file exceeds the {MAX_TASK_FILE_BYTES}-byte safety limit.")
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError("Task file must contain UTF-8 text.") from error


@app.command()
def fix(
    repository_path: Path,
    timeout: int = 120,
    ai: Annotated[
        bool,
        typer.Option(
            "--ai",
            help=(
                "Enable one constrained semantic repair; preview-only unless trusted execution "
                "is enabled."
            ),
        ),
    ] = False,
    prompt_variant: Annotated[
        str,
        typer.Option(
            "--prompt-variant",
            help="Prompt variant used for AI analysis and patch generation.",
        ),
    ] = DEFAULT_PROMPT_VARIANT,
    dry_run: Annotated[
        bool, typer.Option("--dry-run", help="Preview an AI patch without modifying files.")
    ] = False,
    tool_backend: Annotated[
        ToolBackendKind,
        typer.Option("--tool-backend", help="Tool execution backend: local or mcp."),
    ] = ToolBackendKind.LOCAL,
    task: Annotated[
        str | None,
        typer.Option("--task", help="Optional user repair task supplied to semantic analysis."),
    ] = None,
    task_file: Annotated[
        Path | None,
        typer.Option("--task-file", help="Read the optional repair task from a UTF-8 file."),
    ] = None,
    report_json: Annotated[
        Path | None,
        typer.Option(
            "--report-json",
            help="Write a structured, secret-safe local AI repair report.",
        ),
    ] = None,
    trusted_execution: Annotated[
        bool,
        typer.Option(
            "--trusted-execution",
            help=(
                "Run repository commands as the current user and apply AI patches; execution is "
                "NOT sandboxed."
            ),
        ),
    ] = False,
) -> None:
    """Apply one deterministic fix or preview an AI fix; host verification is opt-in."""
    root = repository_path.resolve()
    try:
        prompt_profile(prompt_variant)
        repair_task = _repair_task(task, task_file)
        if dry_run and not ai:
            raise ValueError("--dry-run is available only with --ai.")
        if not ai and (repair_task is not None or report_json is not None):
            raise ValueError("--task, --task-file, and --report-json are available only with --ai.")
        if tool_backend is ToolBackendKind.MCP and not ai:
            raise ValueError("--tool-backend mcp currently requires --ai in fix mode.")
        if tool_backend is ToolBackendKind.MCP and report_json is not None:
            raise ValueError(
                "--report-json is available only with --tool-backend local; "
                "MCP repairs persist resumable repair sessions instead."
            )
        if ai:
            if tool_backend is ToolBackendKind.MCP:
                outcome = execute_mcp_ai_fix(
                    root,
                    provider_from_env(prompt_variant=prompt_variant),
                    timeout=timeout,
                    dry_run=dry_run,
                    trusted_execution=trusted_execution,
                    task=repair_task,
                )
                if outcome.status == "no_candidate":
                    console.print("[yellow]No high-confidence AI fix is available.[/yellow]")
                elif outcome.status in {"dry_run", "preview"}:
                    label = "dry run" if outcome.status == "dry_run" else "safe preview"
                    console.print(f"[cyan]Proposed patch ({label}; no files changed):[/cyan]")
                    console.print(outcome.diff)
                    if outcome.status == "preview":
                        console.print(
                            "[yellow]Use --trusted-execution to submit the patch and run "
                            "unsandboxed repository verification as the current user.[/yellow]"
                        )
                elif outcome.session is not None:
                    console.print(render_repair_session(outcome.session))
                    if outcome.session.pending_operations:
                        _print_repair_approval_instructions(outcome.session)
                    elif outcome.session.phase is RepairPhase.VERIFIED_PASS:
                        console.print("[green]Repair verification passed.[/green]")
                    else:
                        console.print(
                            "[yellow]Repair stopped in state "
                            f"{outcome.session.phase.value.upper()}.[/yellow]"
                        )
                return
            outcome = execute_ai_fix(
                root,
                provider_from_env(prompt_variant=prompt_variant),
                timeout=timeout,
                dry_run=dry_run,
                trusted_execution=trusted_execution,
                task=repair_task,
                prompt_variant=prompt_variant,
                report_path=report_json,
            )
            if outcome.status == "no_candidate":
                console.print("[yellow]No high-confidence AI fix is available.[/yellow]")
            elif outcome.status in {"dry_run", "preview"}:
                label = "dry run" if outcome.status == "dry_run" else "safe preview"
                console.print(f"[cyan]Proposed patch ({label}; no files changed):[/cyan]")
                console.print(outcome.diff)
                if outcome.status == "preview":
                    console.print(
                        "[yellow]Use --trusted-execution to apply the patch and run "
                        "unsandboxed repository verification as the current user.[/yellow]"
                    )
            elif outcome.status == "kept":
                console.print("[green]Patch applied[/green]")
                console.print("[green]Verification passed[/green]")
                console.print("[green]Change kept[/green]")
            else:
                console.print("[yellow]Patch applied[/yellow]")
                console.print(f"[red]Verification failed:[/red] {outcome.verification}")
                console.print("[yellow]Rolling back[/yellow]")
                console.print("[green]Repository restored successfully[/green]")
                raise typer.Exit(1)
            return
        verify_clean_git(root)
        before = scan(root, timeout, verify=trusted_execution)
        change = apply_high_confidence_fix(root)
        if not change:
            console.print("[yellow]No high-confidence fix is available.[/yellow]")
            return
        after = scan(root, timeout, verify=trusted_execution)
        succeeded = after.score >= before.score and all(item.passed for item in after.commands)
        if succeeded:
            console.print(f"[green]Fix succeeded:[/green] {change}")
            if not trusted_execution:
                console.print(
                    "[yellow]Static validation only; repository commands were not run.[/yellow]"
                )
        else:
            console.print(f"[red]Verification failed after fix:[/red] {change}")
            raise typer.Exit(1)
    except (AIError, OSError, ToolBackendError, ValueError) as error:
        console.print(f"[red]Error: {error}[/red]")
        raise typer.Exit(2) from error


if __name__ == "__main__":
    app()
