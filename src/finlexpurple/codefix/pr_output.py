"""Emit a fix as a reviewable diff, or a local branch+commit (Phase 15; §9).

``format_patch`` renders the patch as a clean, PR-ready block (description plus
unified diff). When the target is a git repository, ``create_branch_and_commit``
can put the applied fix on its own branch and commit it locally — but it
**never pushes and never opens a pull request automatically** (§9); handing the
change off for review stays the user's action. Git runs through the hardened
sandbox (argument lists only, no shell).
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from finlexpurple.codefix.patch_generator import Patch
from finlexpurple.tools.sandbox import run_sandboxed


class GitOutputError(RuntimeError):
    """A git operation while emitting a fix failed."""


@dataclass(frozen=True)
class CommitResult:
    """The local branch and commit a fix was placed on (never pushed)."""

    branch: str
    committed: bool
    detail: str


def format_patch(patch: Patch) -> str:
    """Render a patch as a reviewable block: what, why, and the unified diff."""

    return (
        f"# CodeFix: {patch.vulnerability_class}\n"
        f"# {patch.description}\n"
        f"# file: {patch.path}\n\n"
        f"{patch.diff}"
    )


def _git(repo_dir: Path, *args: str) -> str:
    """Run one git command in ``repo_dir`` through the sandbox; return stdout."""

    result = run_sandboxed(["git", "-C", str(repo_dir), *args], timeout=30, cwd=repo_dir)
    if result.timed_out or result.returncode != 0:
        raise GitOutputError(
            f"git {' '.join(args)} failed (exit {result.returncode}): {result.stderr.strip()[:300]}"
        )
    return result.stdout


def is_git_repo(path: Path) -> bool:
    """True if ``path`` is inside a git working tree."""

    try:
        return _git(path, "rev-parse", "--is-inside-work-tree").strip() == "true"
    except GitOutputError:
        return False


def create_branch_and_commit(
    repo_dir: Path,
    patch: Patch,
    *,
    branch: str,
    confirm: bool,
) -> CommitResult:
    """Put the already-applied fix on its own branch and commit it locally.

    Only acts when ``confirm`` is True (the "offer" is the caller's to make).
    Never pushes and never opens a pull request — that is left to the user. The
    patched file must already be written (Agent Fix mode); this stages and
    commits it on a new branch.
    """

    if not confirm:
        return CommitResult(branch=branch, committed=False, detail="Not confirmed; no branch or commit made.")
    if not is_git_repo(repo_dir):
        raise GitOutputError(f"{repo_dir} is not a git repository; cannot create a branch.")

    _git(repo_dir, "checkout", "-b", branch)
    _git(repo_dir, "add", "--", str(patch.path))
    _git(
        repo_dir,
        "commit",
        "-m",
        f"Fix {patch.vulnerability_class}: {patch.description}",
    )
    # Deliberately no `git push` and no PR creation — handoff stays the user's.
    return CommitResult(
        branch=branch,
        committed=True,
        detail=f"Committed the fix on branch {branch!r} locally (not pushed, no PR opened).",
    )
