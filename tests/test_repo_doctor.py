import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from typer.testing import CliRunner

from repo_doctor.cli import app
from repo_doctor.detector import detect_technologies, discover_commands
from repo_doctor.fixer import apply_high_confidence_fix, verify_clean_git
from repo_doctor.models import ScanResult
from repo_doctor.report import render_report
from repo_doctor.runner import run_command
from repo_doctor.scanner import scan

FIXTURE = Path(__file__).parent / "fixtures" / "python_project"


def test_detect_and_discover() -> None:
    technologies = detect_technologies(FIXTURE)
    assert technologies == ["Python"]
    assert ("Python tests", ("pytest",)) in discover_commands(FIXTURE, technologies)


def test_scan_and_report_does_not_modify_source(tmp_path: Path) -> None:
    target = tmp_path / "project"
    shutil.copytree(FIXTURE, target)
    before = {p.relative_to(target): p.read_bytes() for p in target.rglob("*") if p.is_file()}
    result = scan(target, verify=True)
    after = {p.relative_to(target): p.read_bytes() for p in target.rglob("*") if p.is_file()}
    report = render_report(result)
    assert before == after
    assert result.score == 100, result.commands
    assert "## Health Score (0-100)" in report
    assert "Python tests: PASS" in report
    assert "AI Semantic Analysis: Not requested" in report


def test_cli_writes_report(tmp_path: Path) -> None:
    output = tmp_path / "health.md"
    response = CliRunner().invoke(app, ["scan", str(FIXTURE), "--output", str(output)])
    assert response.exit_code == 0, response.output
    assert "Health score: 100/100" in response.output
    assert output.exists()


def test_cli_does_not_resolve_provider_without_ai(tmp_path: Path, monkeypatch) -> None:
    def fail_if_called():
        raise AssertionError("provider must not be resolved")

    monkeypatch.setattr("repo_doctor.cli.provider_from_env", fail_if_called)
    monkeypatch.setattr(
        "repo_doctor.cli.scan",
        lambda root, timeout, **_kwargs: ScanResult(root.resolve(), [], 0, 0, []),
    )
    response = CliRunner().invoke(app, ["scan", str(tmp_path)])
    assert response.exit_code == 0, response.output
    assert "AI Semantic Analysis: Not requested" in response.output


def test_cli_ai_mode_reports_missing_configuration(tmp_path: Path, monkeypatch) -> None:
    for name in ("REPO_DOCTOR_API_KEY", "REPO_DOCTOR_BASE_URL", "REPO_DOCTOR_MODEL"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(
        "repo_doctor.cli.scan",
        lambda root, timeout, **_kwargs: ScanResult(root.resolve(), [], 0, 0, []),
    )
    response = CliRunner().invoke(app, ["scan", str(tmp_path), "--ai"])
    assert response.exit_code == 0, response.output
    assert "required configuration is missing" in response.output


def test_cli_ai_mode_reports_invalid_request_timeout(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REPO_DOCTOR_API_KEY", "test-key")
    monkeypatch.setenv("REPO_DOCTOR_BASE_URL", "https://provider.invalid/v1")
    monkeypatch.setenv("REPO_DOCTOR_MODEL", "test-model")
    monkeypatch.setenv("REPO_DOCTOR_REQUEST_TIMEOUT", "invalid")
    monkeypatch.setattr(
        "repo_doctor.cli.scan",
        lambda root, timeout, **_kwargs: ScanResult(root.resolve(), [], 0, 0, []),
    )
    response = CliRunner().invoke(app, ["scan", str(tmp_path), "--ai"])
    assert response.exit_code == 0, response.output
    assert "positive finite number of seconds" in response.output
    assert "Traceback" not in response.output


def test_fixer_requires_git_and_fixes_one_file(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="Git repository"):
        verify_clean_git(tmp_path)
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    file = tmp_path / "example.py"
    file.write_text("value = 1  \n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(tmp_path),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=t@example.com",
            "commit",
            "-qm",
            "fixture",
        ],
        check=True,
    )
    verify_clean_git(tmp_path)
    assert apply_high_confidence_fix(tmp_path) == "Removed trailing whitespace from example.py"
    assert file.read_text(encoding="utf-8") == "value = 1\n"


def test_verification_subprocess_does_not_inherit_provider_key(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("REPO_DOCTOR_API_KEY", "must-not-reach-project")
    monkeypatch.setenv("GH_TOKEN", "also-must-not-reach-project")
    command = (
        sys.executable,
        "-c",
        "import os; print(os.environ.get('REPO_DOCTOR_API_KEY', 'absent'), "
        "os.environ.get('GH_TOKEN', 'absent'))",
    )
    result = run_command("environment check", command, tmp_path)
    assert result.passed
    assert result.stdout.strip() == "absent absent"


def test_python_tool_fallback_does_not_require_console_script_on_path(
    tmp_path: Path, monkeypatch
) -> None:
    real_run = subprocess.run

    def missing_console_script(command, *args, **kwargs):
        if command[0] == "pytest":
            raise FileNotFoundError
        return real_run(command, *args, **kwargs)

    monkeypatch.setattr("repo_doctor.runner.subprocess.run", missing_console_script)
    result = run_command("Python tests", ("pytest", "--version"), tmp_path)
    assert result.passed, result.stderr
    assert result.command[1:3] == ("-m", "pytest")
