"""Sandboxed external-process execution (Phase 7; decisions.md §15, §20).

The one place external tools are run. The execution contract every wrapped
scanner (Phase 13/14) runs under:

* **Argument lists only** — a command is a ``list[str]``; passing a shell string
  is a ``TypeError``. Nothing is ever run through a shell, so target/tool input
  cannot be interpolated into a shell command.
* **Enforced timeout** — a process that exceeds its timeout is *killed* (its
  whole process group on POSIX), never left running.
* **stdout/stderr captured separately**, returncode surfaced, with a minimal
  environment by default (only ``PATH`` unless the caller passes ``env``), so a
  wrapped tool does not inherit the parent's secrets.
* **Restricted working directory** — runs in ``cwd`` (a temp dir by default),
  never the repository or an arbitrary location.
"""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import tempfile
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from time import monotonic


@dataclass(frozen=True)
class ToolResult:
    """The structured outcome of one sandboxed process run."""

    argv: tuple[str, ...]
    returncode: int | None
    stdout: str
    stderr: str
    timed_out: bool
    duration_seconds: float


def run_sandboxed(
    argv: Sequence[str],
    *,
    timeout: float,
    cwd: Path | None = None,
    env: Mapping[str, str] | None = None,
    input_text: str | None = None,
) -> ToolResult:
    """Run ``argv`` with no shell, an enforced timeout, and separated output.

    ``argv`` must be a sequence of strings (a bare ``str`` is rejected so a shell
    string can never be passed). On timeout the process group is killed and a
    result with ``timed_out=True`` is returned rather than leaving it running.
    """

    if isinstance(argv, (str, bytes)):
        raise TypeError("argv must be a list of arguments, never a shell string.")
    args = [str(a) for a in argv]
    if not args:
        raise ValueError("argv must contain at least the program to run.")
    if timeout <= 0:
        raise ValueError("timeout must be positive.")

    run_env = {"PATH": os.environ.get("PATH", "")} if env is None else dict(env)
    posix = os.name != "nt"
    started = monotonic()
    with tempfile.TemporaryDirectory(prefix="flp-sandbox-") as default_cwd:
        workdir = str(cwd) if cwd is not None else default_cwd
        # args is a validated list and shell is never used (see the contract above).
        process = subprocess.Popen(
            args,
            cwd=workdir,
            env=run_env,
            stdin=subprocess.PIPE if input_text is not None else subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            shell=False,
            start_new_session=posix,
        )
        timed_out = False
        try:
            stdout, stderr = process.communicate(input=input_text, timeout=timeout)
        except subprocess.TimeoutExpired:
            timed_out = True
            _terminate(process)
            stdout, stderr = process.communicate()
        return ToolResult(
            argv=tuple(args),
            returncode=None if timed_out else process.returncode,
            stdout=stdout or "",
            stderr=stderr or "",
            timed_out=timed_out,
            duration_seconds=monotonic() - started,
        )


def _terminate(process: subprocess.Popen[str]) -> None:
    """Kill a timed-out process (its whole group on POSIX) so nothing is left running."""

    try:
        if sys.platform != "win32":
            os.killpg(os.getpgid(process.pid), signal.SIGKILL)
        else:
            process.kill()
    except (ProcessLookupError, PermissionError, OSError):
        # Fall back to killing just the process if the group kill is unavailable.
        try:
            process.kill()
        except OSError:
            pass
