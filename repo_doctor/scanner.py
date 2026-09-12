"""Read-only repository scanning orchestration."""

import shutil
import tempfile
from pathlib import Path

from .analyzer import analyze, is_utf8_text_file, text_files
from .backends import LocalToolBackend, ToolBackend
from .detector import detect_technologies, discover_commands
from .models import ScanResult
from .runner import run_command

CONFIG_NAMES = {
    "README.md",
    "README.rst",
    "pyproject.toml",
    "requirements.txt",
    "package.json",
    "pytest.ini",
    "ruff.toml",
    ".eslintrc",
    ".eslintrc.json",
}
COPY_EXCLUDES = (
    ".git",
    "node_modules",
    ".venv",
    "__pycache__",
    ".pytest_cache",
    ".ruff_cache",
    ".repo-doctor",
)


def _copy_ignore(directory: str, names: list[str]) -> set[str]:
    """Exclude tool data and all symlinks from the verification staging copy."""
    ignored = set(shutil.ignore_patterns(*COPY_EXCLUDES)(directory, names))
    parent = Path(directory)
    ignored.update(name for name in names if (parent / name).is_symlink())
    return ignored


def scan(
    root: Path,
    timeout: int = 120,
    backend: ToolBackend | None = None,
    *,
    verify: bool = False,
) -> ScanResult:
    """Inspect *root* statically and optionally run trusted host verification."""
    root = root.resolve()
    if not root.is_dir():
        raise ValueError(f"Repository path is not a directory: {root}")
    backend = backend or LocalToolBackend(root)
    files = list(text_files(root))
    lines = 0
    with backend:
        for path in files:
            if not is_utf8_text_file(path):
                continue
            content = backend.read_file(path.relative_to(root).as_posix()).content
            lines += len(content.splitlines())
        inspected = sorted(
            path.name
            for path in files
            if path.parent == root
            and (
                path.name in CONFIG_NAMES
                or path.name.lower() == "readme"
                or path.name.lower().startswith("readme.")
            )
        )
        technologies = detect_technologies(root)
        verification_plan = discover_commands(root, technologies)
        result = ScanResult(
            root,
            technologies,
            len(files),
            lines,
            inspected,
            verification_plan=verification_plan,
        )
        if not verify:
            pass
        elif backend.verification_in_place:
            for name, command in verification_plan:
                result.commands.append(backend.run_command(name, command, ".", timeout))
        else:
            with tempfile.TemporaryDirectory(prefix="repo-doctor-") as temporary:
                copy = Path(temporary) / "repository"
                shutil.copytree(
                    root,
                    copy,
                    ignore=_copy_ignore,
                )
                for name, command in verification_plan:
                    result.commands.append(run_command(name, command, copy, timeout))
    analyze(result)
    return result
