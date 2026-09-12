import json
import subprocess
from pathlib import Path

import pytest

from repo_doctor.ai.errors import VerificationError
from repo_doctor.ai.fixer import execute_ai_fix
from repo_doctor.ai.models import AnalysisResponse, PatchProposal, SemanticFinding, Severity
from repo_doctor.models import CommandResult, ScanResult


class RepairProvider:
    def __init__(self) -> None:
        self.patch_request = None

    def analyze(self, request):
        return AnalysisResponse(
            (
                SemanticFinding(
                    "boundary-1",
                    "Exact stock is rejected",
                    "control-flow",
                    Severity.HIGH,
                    0.95,
                    "inventory.py",
                    2,
                    2,
                    "Equality is a valid fulfillment case.",
                    "The code uses requested < stock.",
                    "Change the comparison to <=.",
                ),
            )
        )

    def generate_patch(self, request):
        self.patch_request = request
        return PatchProposal(
            "inventory.py",
            "return requested < stock",
            "return requested <= stock",
            "Accept the equality boundary",
            0.96,
        )


class ObservableSourceProvider(RepairProvider):
    def __init__(self, sentinel: Path) -> None:
        super().__init__()
        self.sentinel = sentinel

    def generate_patch(self, request):
        self.patch_request = request
        return PatchProposal(
            "inventory.py",
            "def can_fulfill(stock, requested):",
            (
                "from pathlib import Path\n"
                f"Path({str(self.sentinel)!r}).write_text('executed', encoding='utf-8')\n\n"
                "def can_fulfill(stock, requested):"
            ),
            "Observable provider-written import behavior",
            0.96,
        )


def initialize_repository(root: Path) -> bytes:
    (root / "pyproject.toml").write_text("[project]\nname='fixture'\nversion='1.0'\n")
    target = root / "inventory.py"
    target.write_bytes(b"def can_fulfill(stock, requested):\r\n    return requested < stock\r\n")
    subprocess.run(["git", "init", "-q", str(root)], check=True)
    subprocess.run(["git", "-C", str(root), "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(root),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-qm",
            "fixture",
        ],
        check=True,
    )
    return target.read_bytes()


def verification_result(root: Path, passed: bool = True) -> ScanResult:
    command = CommandResult("Python tests", ("pytest",), 0 if passed else 1, "", "", 0.01)
    score = 100 if passed else 75
    return ScanResult(
        root,
        ["Python"],
        2,
        3,
        ["pyproject.toml"],
        commands=[command],
        deterministic_score=score,
        score=score,
    )


def test_successful_ai_fix_runs_verification_and_keeps_change(tmp_path: Path) -> None:
    initialize_repository(tmp_path)
    calls = 0

    def scanner(root: Path, timeout: int) -> ScanResult:
        nonlocal calls
        calls += 1
        return verification_result(root)

    outcome = execute_ai_fix(
        tmp_path,
        RepairProvider(),
        scan_function=scanner,
        trusted_execution=True,
    )
    assert outcome.status == "kept"
    assert calls == 2
    assert "requested <= stock" in (tmp_path / "inventory.py").read_text(encoding="utf-8")


def test_failed_verification_rolls_back_exact_bytes(tmp_path: Path) -> None:
    original = initialize_repository(tmp_path)
    calls = 0

    def scanner(root: Path, timeout: int) -> ScanResult:
        nonlocal calls
        calls += 1
        return verification_result(root, passed=calls == 1)

    outcome = execute_ai_fix(
        tmp_path,
        RepairProvider(),
        scan_function=scanner,
        trusted_execution=True,
    )
    assert outcome.status == "rolled_back"
    assert (tmp_path / "inventory.py").read_bytes() == original
    status = subprocess.run(
        ["git", "-C", str(tmp_path), "status", "--porcelain"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert status.stdout == ""


def test_verification_exception_rolls_back(tmp_path: Path) -> None:
    original = initialize_repository(tmp_path)
    calls = 0

    def scanner(root: Path, timeout: int) -> ScanResult:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("verification unavailable")
        return verification_result(root)

    outcome = execute_ai_fix(
        tmp_path,
        RepairProvider(),
        scan_function=scanner,
        trusted_execution=True,
    )
    assert outcome.status == "rolled_back"
    assert "could not complete" in outcome.verification
    assert (tmp_path / "inventory.py").read_bytes() == original


def test_verification_timeout_rolls_back(tmp_path: Path) -> None:
    original = initialize_repository(tmp_path)
    calls = 0

    def scanner(root: Path, timeout: int) -> ScanResult:
        nonlocal calls
        calls += 1
        result = verification_result(root)
        if calls == 2:
            result.commands[0] = CommandResult(
                "Python tests", ("pytest",), 124, "", "timed out", 1.0, timed_out=True
            )
            result.deterministic_score = 75
            result.score = 75
        return result

    outcome = execute_ai_fix(
        tmp_path,
        RepairProvider(),
        scan_function=scanner,
        trusted_execution=True,
    )
    assert outcome.status == "rolled_back"
    assert (tmp_path / "inventory.py").read_bytes() == original


def test_dry_run_performs_no_modification(tmp_path: Path) -> None:
    original = initialize_repository(tmp_path)
    calls = 0

    def scanner(root: Path, timeout: int) -> ScanResult:
        nonlocal calls
        calls += 1
        return verification_result(root)

    outcome = execute_ai_fix(tmp_path, RepairProvider(), dry_run=True, scan_function=scanner)
    assert outcome.status == "dry_run"
    assert "-    return requested < stock" in outcome.diff
    assert calls == 1
    assert (tmp_path / "inventory.py").read_bytes() == original


def test_default_ai_fix_previews_without_executing_provider_written_source(
    tmp_path: Path,
) -> None:
    original = initialize_repository(tmp_path)
    tests = tmp_path / "tests"
    tests.mkdir()
    (tests / "test_inventory.py").write_text(
        "from inventory import can_fulfill\n\ndef test_smoke():\n    assert can_fulfill(2, 1)\n",
        encoding="utf-8",
    )
    subprocess.run(["git", "-C", str(tmp_path), "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(tmp_path),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.com",
            "commit",
            "-qm",
            "add tests",
        ],
        check=True,
    )
    sentinel = tmp_path.parent / f"{tmp_path.name}-provider-code-executed"

    outcome = execute_ai_fix(tmp_path, ObservableSourceProvider(sentinel))

    assert outcome.status == "preview"
    assert "provider-written import behavior" not in (tmp_path / "inventory.py").read_text(
        encoding="utf-8"
    )
    assert (tmp_path / "inventory.py").read_bytes() == original
    assert not sentinel.exists()


def test_ai_fix_refuses_to_patch_without_verification_commands(tmp_path: Path) -> None:
    initialize_repository(tmp_path)

    def scanner(root: Path, timeout: int) -> ScanResult:
        return ScanResult(root, ["Python"], 2, 3, ["pyproject.toml"])

    with pytest.raises(VerificationError, match="at least one"):
        execute_ai_fix(
            tmp_path,
            RepairProvider(),
            scan_function=scanner,
            trusted_execution=True,
        )


def test_complete_behavioral_contract_enters_patch_request(tmp_path: Path) -> None:
    initialize_repository(tmp_path)
    provider = RepairProvider()

    execute_ai_fix(
        tmp_path,
        provider,
        task="Accept exact stock and preserve smaller requests.",
        scan_function=lambda root, _timeout: verification_result(root),
    )

    assert provider.patch_request is not None
    contract = provider.patch_request.behavioral_contract
    assert any("Satisfy the user task" in item for item in contract.must_fix)
    assert any("boundary-1" in item for item in contract.must_fix)
    assert any("passing baseline verification" in item for item in contract.must_preserve)


def test_failed_verification_report_preserves_attempted_patch_before_rollback(
    tmp_path: Path,
    monkeypatch,
) -> None:
    original = initialize_repository(tmp_path)
    report_path = tmp_path.parent / f"{tmp_path.name}-repair-report.json"
    calls = 0

    def scanner(root: Path, timeout: int) -> ScanResult:
        nonlocal calls
        calls += 1
        result = verification_result(root, passed=calls == 1)
        if calls == 2:
            result.commands[0] = CommandResult(
                "Python tests",
                ("pytest", "-q"),
                1,
                "1 passed, 1 failed",
                "assertion failed",
                0.2,
            )
        return result

    from repo_doctor.ai import fixer as fixer_module

    real_rollback = fixer_module.rollback_patch
    observed_before_rollback = {}

    def checking_rollback(prepared) -> None:
        observed_before_rollback.update(json.loads(report_path.read_text(encoding="utf-8")))
        real_rollback(prepared)

    monkeypatch.setattr(fixer_module, "rollback_patch", checking_rollback)

    outcome = execute_ai_fix(
        tmp_path,
        RepairProvider(),
        prompt_variant="candidate-v3",
        report_path=report_path,
        scan_function=scanner,
        trusted_execution=True,
    )

    report = json.loads(report_path.read_text(encoding="utf-8"))
    assert outcome.status == "rolled_back"
    assert observed_before_rollback["final_status"] == "verification_failed_pending_rollback"
    assert "requested <= stock" in observed_before_rollback["patch"]["diff"]
    assert report["prompt_variant"] == "candidate-v3"
    assert report["selected_finding"]["id"] == "boundary-1"
    assert report["behavioral_contract"]["must_fix"]
    assert report["patch_applied"] is True
    assert "requested <= stock" in report["patch"]["diff"]
    assert report["verification"]["commands"][0]["command"] == ["pytest", "-q"]
    assert report["verification"]["commands"][0]["returncode"] == 1
    assert report["verification"]["commands"][0]["stdout_summary"] == "1 passed, 1 failed"
    assert report["verification"]["commands"][0]["stderr_summary"] == "assertion failed"
    assert report["rollback_attempted"] is True
    assert report["rollback_succeeded"] is True
    assert report["final_status"] == "rolled_back"
    assert (tmp_path / "inventory.py").read_bytes() == original


def test_repair_report_redacts_and_bounds_secrets(tmp_path: Path, monkeypatch) -> None:
    secret = "provider-secret-value-123456"
    monkeypatch.setenv("REPO_DOCTOR_API_KEY", secret)
    initialize_repository(tmp_path)
    report_path = tmp_path.parent / f"{tmp_path.name}-secret-report.json"
    calls = 0

    def scanner(root: Path, timeout: int) -> ScanResult:
        nonlocal calls
        calls += 1
        result = verification_result(root, passed=calls == 1)
        if calls == 2:
            result.commands[0] = CommandResult(
                "Python tests",
                ("pytest",),
                1,
                f"Authorization: Bearer {secret}",
                f"api_key={secret}",
                0.1,
            )
        return result

    execute_ai_fix(
        tmp_path,
        RepairProvider(),
        task=f"password={secret}\n" + "x" * 20_000,
        report_path=report_path,
        scan_function=scanner,
        trusted_execution=True,
    )

    report_bytes = report_path.read_bytes()
    report = json.loads(report_bytes)
    assert secret.encode() not in report_bytes
    assert "[REDACTED]" in repr(report)
    assert len(report["behavioral_contract"]["must_fix"][0]) <= 8_000
