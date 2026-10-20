"""Phase 7 acceptance item 2: the sandboxed process runner (decisions.md §15/§20)."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from finlexpurple.tools.sandbox import run_sandboxed


def test_runs_a_command_and_captures_output_separately() -> None:
    result = run_sandboxed(
        [sys.executable, "-c", "import sys; print('out'); print('err', file=sys.stderr)"],
        timeout=10,
    )
    assert result.returncode == 0
    assert result.timed_out is False
    assert "out" in result.stdout
    assert "err" in result.stderr


def test_a_shell_string_is_rejected() -> None:
    # Passing a string (which could be a shell command) is a TypeError.
    with pytest.raises(TypeError, match="never a shell string"):
        run_sandboxed("echo hello; rm -rf /", timeout=5)  # type: ignore[arg-type]


def test_a_process_exceeding_its_timeout_is_killed_not_left_running() -> None:
    result = run_sandboxed(
        [sys.executable, "-c", "import time; time.sleep(30)"],
        timeout=0.5,
    )
    assert result.timed_out is True
    assert result.returncode is None
    # It returned promptly (killed), not after the full 30s sleep.
    assert result.duration_seconds < 10


def test_nonzero_exit_is_surfaced_not_raised() -> None:
    result = run_sandboxed([sys.executable, "-c", "import sys; sys.exit(3)"], timeout=10)
    assert result.returncode == 3
    assert result.timed_out is False


def test_runs_in_the_given_working_directory(tmp_path: Path) -> None:
    result = run_sandboxed(
        [sys.executable, "-c", "import os; print(os.getcwd())"],
        timeout=10,
        cwd=tmp_path,
    )
    assert str(tmp_path.resolve()) in Path(result.stdout.strip()).resolve().as_posix() or \
        result.stdout.strip() == str(tmp_path)


def test_default_env_strips_secrets_but_preserves_runtime_vars(monkeypatch) -> None:
    # A secret-named var must not reach the tool; a normal var and PATH must.
    monkeypatch.setenv("FINLEXPURPLE_DEMO_API_KEY", "super-secret")
    monkeypatch.setenv("FINLEXPURPLE_DEMO_PUBLIC", "ok")
    result = run_sandboxed(
        [sys.executable, "-c", "import os, json; print(json.dumps(dict(os.environ)))"],
        timeout=10,
    )
    assert result.returncode == 0, result.stderr  # Python actually started (needs SYSTEMROOT on Windows)
    child_env = json.loads(result.stdout.strip())
    assert "FINLEXPURPLE_DEMO_API_KEY" not in child_env  # secret stripped
    assert child_env.get("FINLEXPURPLE_DEMO_PUBLIC") == "ok"  # non-secret preserved
    assert "PATH" in child_env


def test_empty_argv_and_bad_timeout_are_rejected() -> None:
    with pytest.raises(ValueError):
        run_sandboxed([], timeout=5)
    with pytest.raises(ValueError):
        run_sandboxed([sys.executable, "-c", "pass"], timeout=0)
