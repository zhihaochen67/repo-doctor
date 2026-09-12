import os
import sys
from pathlib import Path

import pytest

import repo_doctor.scanner as scanner_module
from repo_doctor.ai.models import AnalysisResponse, PatchProposal
from repo_doctor.ai.prompts import analysis_messages
from repo_doctor.ai.workflow import analyze_repository
from repo_doctor.detector import detect_technologies, discover_commands
from repo_doctor.fixer import apply_high_confidence_fix, verify_clean_git
from repo_doctor.models import CommandResult, ScanResult
from repo_doctor.report import render_report
from repo_doctor.runner import run_command
from repo_doctor.security import redact_sensitive_text


class EmptyProvider:
    def __init__(self) -> None:
        self.request = None

    def analyze(self, request):
        self.request = request
        return AnalysisResponse(())

    def generate_patch(self, request):
        return PatchProposal(request.file.path, "before", "after", "unused", 0.95)


def test_legacy_fixer_skips_symlink_candidates(tmp_path: Path, monkeypatch) -> None:
    root = tmp_path / "repository"
    root.mkdir()
    outside = tmp_path / "outside.py"
    outside.write_bytes(b"value = 1  \n")
    candidate = root / "linked.py"
    simulated = False
    try:
        candidate.symlink_to(outside)
    except OSError:
        simulated = True
        candidate.write_bytes(outside.read_bytes())
        original_is_symlink = Path.is_symlink
        monkeypatch.setattr(
            Path,
            "is_symlink",
            lambda path: path == candidate or original_is_symlink(path),
        )

    assert apply_high_confidence_fix(root) is None
    assert outside.read_bytes() == b"value = 1  \n"
    if simulated:
        assert candidate.read_bytes() == b"value = 1  \n"


def test_verification_output_is_redacted_before_prompt_serialization(
    tmp_path: Path, monkeypatch
) -> None:
    monkeypatch.setenv("TEST_API_TOKEN", "literal-secret-value")
    (tmp_path / "app.py").write_text("VALUE = 1\n", encoding="utf-8")
    verification = CommandResult(
        "Python tests",
        ("pytest",),
        1,
        "TEST_API_TOKEN=literal-secret-value\n",
        "Authorization: Bearer literal-secret-value\n",
        0.1,
    )
    result = ScanResult(
        tmp_path,
        ["Python"],
        1,
        1,
        [],
        commands=[verification],
        deterministic_score=75,
        score=75,
    )
    provider = EmptyProvider()

    analyze_repository(result, provider)

    assert provider.request is not None
    evidence = provider.request.verifications[0]
    assert "literal-secret-value" not in evidence.stdout + evidence.stderr
    serialized = str(analysis_messages(provider.request))
    assert "literal-secret-value" not in serialized


def test_command_output_replaces_invalid_utf8_bytes(tmp_path: Path) -> None:
    command = (
        sys.executable,
        "-c",
        "import sys; sys.stdout.buffer.write(b'valid\\xffoutput'); "
        "sys.stderr.buffer.write(b'error\\xfeoutput')",
    )
    result = run_command("encoding check", command, tmp_path)
    assert result.passed
    assert result.stdout == "valid\ufffdoutput"
    assert result.stderr == "error\ufffdoutput"


@pytest.mark.skipif(os.name != "nt", reason="Windows launcher behavior")
def test_node_discovery_uses_npm_cmd_on_windows(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text(
        '{"scripts":{"test":"node test.js","lint":"node lint.js"}}', encoding="utf-8"
    )
    commands = discover_commands(tmp_path, ["Node.js"])
    assert commands == [
        ("Node tests", ("npm.cmd", "test")),
        ("Node lint", ("npm.cmd", "run", "lint")),
    ]


def test_non_utf8_package_json_is_ignored(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_bytes(b'{"scripts":\xff}')
    technologies = detect_technologies(tmp_path)
    assert technologies == ["Node.js"]
    assert discover_commands(tmp_path, technologies) == []


@pytest.mark.parametrize("content", ["[]", '{"scripts":[]}'])
def test_package_json_with_unexpected_schema_is_ignored(tmp_path: Path, content: str) -> None:
    (tmp_path / "package.json").write_text(content, encoding="utf-8")
    assert discover_commands(tmp_path, ["Node.js"]) == []


def test_scan_excludes_symlinks_from_temporary_copy(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "pyproject.toml").write_text("[tool.ruff]\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    candidate = tmp_path / "external-link.py"
    candidate.write_text("VALUE = 1\n", encoding="utf-8")
    original_is_symlink = Path.is_symlink
    monkeypatch.setattr(
        Path,
        "is_symlink",
        lambda path: path == candidate or original_is_symlink(path),
    )

    def verify_copy(name, command, cwd, timeout):
        assert not (cwd / candidate.name).exists()
        return CommandResult(name, command, 0, "", "", 0.01)

    monkeypatch.setattr(scanner_module, "run_command", verify_copy)
    result = scanner_module.scan(tmp_path, verify=True)
    assert all(command.passed for command in result.commands)


def test_scan_skips_broken_symlink_when_supported(tmp_path: Path, monkeypatch) -> None:
    (tmp_path / "pyproject.toml").write_text("[tool.ruff]\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    try:
        (tmp_path / "broken.py").symlink_to(tmp_path / "missing.py")
    except OSError as error:
        pytest.skip(f"symlink creation is unavailable: {error}")

    monkeypatch.setattr(
        scanner_module,
        "run_command",
        lambda name, command, cwd, timeout: CommandResult(name, command, 0, "", "", 0.01),
    )
    result = scanner_module.scan(tmp_path, verify=True)
    assert all(command.passed for command in result.commands)


def _observable_pytest_repository(root: Path, sentinel: Path) -> None:
    (root / "requirements.txt").write_text("pytest\n", encoding="utf-8")
    (root / "README.md").write_text("# Observable fixture\n", encoding="utf-8")
    (root / "conftest.py").write_text(
        "from pathlib import Path\n"
        f"Path({str(sentinel)!r}).write_text('executed', encoding='utf-8')\n",
        encoding="utf-8",
    )
    tests = root / "tests"
    tests.mkdir()
    (tests / "test_ok.py").write_text("def test_ok():\n    assert True\n", encoding="utf-8")


def test_default_scan_discovers_but_does_not_execute_repository_verification(
    tmp_path: Path,
) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    sentinel = tmp_path / "pytest-executed"
    _observable_pytest_repository(repository, sentinel)

    result = scanner_module.scan(repository)

    assert not sentinel.exists()
    assert result.technologies == ["Python"]
    assert result.files == 4
    assert result.commands == []
    assert result.verification_plan == [("Python tests", ("pytest",))]
    assert "No supported test or lint commands were discovered." not in (
        result.potential_bugs + result.maintainability_issues
    )
    report = render_report(result)
    assert "Discovered but intentionally not run in safe mode: `pytest`" in report


def test_trusted_execution_runs_discovered_repository_verification(tmp_path: Path) -> None:
    repository = tmp_path / "repository"
    repository.mkdir()
    sentinel = tmp_path / "pytest-executed"
    _observable_pytest_repository(repository, sentinel)

    result = scanner_module.scan(repository, verify=True)

    assert sentinel.read_text(encoding="utf-8") == "executed"
    assert [item.name for item in result.commands] == ["Python tests"]
    assert result.commands[0].passed


@pytest.mark.parametrize(
    ("name", "content"),
    [
        ("README.md", "Hard line break here.  \nNext line.\n"),
        ("message.py", 'MESSAGE = """First line  \nSecond line."""\n'),
    ],
)
def test_legacy_fixer_preserves_semantic_trailing_whitespace(
    tmp_path: Path, name: str, content: str
) -> None:
    target = tmp_path / name
    target.write_text(content, encoding="utf-8")
    assert apply_high_confidence_fix(tmp_path) is None
    assert target.read_text(encoding="utf-8") == content


@pytest.mark.parametrize("name", ["readme.md", "README", "Readme.rst", "README.txt"])
def test_scan_recognizes_common_readme_names(tmp_path: Path, name: str) -> None:
    (tmp_path / name).write_text("# Project\n", encoding="utf-8")
    result = scanner_module.scan(tmp_path)
    assert name in result.inspected_files
    assert "No README was found at the repository root." not in result.maintainability_issues


def test_node_discovery_does_not_force_jest_arguments(tmp_path: Path) -> None:
    (tmp_path / "package.json").write_text('{"scripts":{"test":"mocha test"}}', encoding="utf-8")
    npm = "npm.cmd" if os.name == "nt" else "npm"
    assert discover_commands(tmp_path, ["Node.js"]) == [("Node tests", (npm, "test"))]


def test_verify_clean_git_reports_missing_git_actionably(tmp_path: Path, monkeypatch) -> None:
    def missing_git(*args, **kwargs):
        raise FileNotFoundError

    monkeypatch.setattr("repo_doctor.fixer.subprocess.run", missing_git)
    with pytest.raises(ValueError, match="Git is required for fix mode"):
        verify_clean_git(tmp_path)


def test_secret_redaction_keeps_strong_and_labeled_secrets_hidden(monkeypatch) -> None:
    monkeypatch.setenv("SERVICE_API_TOKEN", "abcd1234-super-secret")
    monkeypatch.setenv("SHORT_SECRET", "true")
    text = "leak: abcd1234-super-secret\nSECRET=true\nAuthorization: Bearer bearer-value\n"
    redacted = redact_sensitive_text(text)
    assert "abcd1234-super-secret" not in redacted
    assert "SECRET=true" not in redacted
    assert "bearer-value" not in redacted


def test_secret_redaction_does_not_corrupt_unrelated_source_text(monkeypatch) -> None:
    monkeypatch.setenv("SHORT_SECRET", "true")
    monkeypatch.setenv("TEST_API_TOKEN", "key1")
    source = "enabled = true\nmonkey1 = public_key1\n"
    assert redact_sensitive_text(source) == source
