"""Phase 15: diff output and local git branch/commit (never push, never PR)."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from finlexpurple.codefix.parser import CodeLanguage
from finlexpurple.codefix.patch_generator import generate_patch
from finlexpurple.codefix.pr_output import (
    create_branch_and_commit,
    format_patch,
    is_git_repo,
)
from finlexpurple.codefix.safety_checks import apply_patch
from finlexpurple.gates.fix_mode import FixMode

_VULN = "import yaml\nobj = yaml.load(data)\n"


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, check=True
    ).stdout


def test_format_patch_contains_description_and_diff(tmp_path: Path) -> None:
    patch = generate_patch(tmp_path / "c.py", _VULN, CodeLanguage.PYTHON)
    assert patch is not None
    out = format_patch(patch)
    assert "insecure_deserialization" in out
    assert "safe_load" in out


def test_is_git_repo_false_for_plain_dir(tmp_path: Path) -> None:
    assert is_git_repo(tmp_path) is False


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    _git(tmp_path, "init")
    _git(tmp_path, "config", "user.email", "dev@example.invalid")
    _git(tmp_path, "config", "user.name", "Dev")
    (tmp_path / "c.py").write_text(_VULN, encoding="utf-8")
    _git(tmp_path, "add", "c.py")
    _git(tmp_path, "commit", "-m", "baseline")
    return tmp_path


def test_create_branch_and_commit_locally_without_pushing(git_repo: Path) -> None:
    patch = generate_patch(git_repo / "c.py", _VULN, CodeLanguage.PYTHON)
    assert patch is not None
    apply_patch(patch, fix_mode=FixMode.AGENT)  # write the fix first

    result = create_branch_and_commit(git_repo, patch, branch="flp/fix-yaml", confirm=True)

    assert result.committed is True
    assert _git(git_repo, "rev-parse", "--abbrev-ref", "HEAD").strip() == "flp/fix-yaml"
    assert "insecure_deserialization" in _git(git_repo, "log", "-1", "--pretty=%s")
    # Proof nothing was pushed: there is no remote at all.
    assert _git(git_repo, "remote").strip() == ""


def test_not_confirmed_makes_no_branch(git_repo: Path) -> None:
    patch = generate_patch(git_repo / "c.py", _VULN, CodeLanguage.PYTHON)
    assert patch is not None
    result = create_branch_and_commit(git_repo, patch, branch="flp/fix", confirm=False)
    assert result.committed is False
    assert _git(git_repo, "rev-parse", "--abbrev-ref", "HEAD").strip() in {"main", "master"}
