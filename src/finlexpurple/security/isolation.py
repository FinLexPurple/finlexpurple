"""Tiered container isolation for the agent's own execution (decisions.md §27).

The scan runs inside an isolated environment, not directly on the host. This
module builds all three tiers and enforces the strict host↔container boundary.

* **None** — runs on the host, only after an explicit warning. For machines
  without Docker or users who accept the trade-off.
* **Standard** (the default) — a hardened ``docker run``: read-only root
  filesystem, all Linux capabilities dropped, ``no-new-privileges``, a non-root
  user, pid/memory limits, no network by default, and **only two mounts cross
  the boundary** — the target source read-only at ``/work/src`` and a single
  writable output dir at ``/work/out``. It **never** mounts the Docker socket
  and **never** runs privileged (decisions.md §15). If Standard is selected but
  Docker is unavailable, the run refuses rather than silently running on the
  host.
* **Maximum** (gVisor) — Phase 20 self-isolation hardening, explicitly distinct
  from the Phase 14 container-testing module. It adds the ``runsc`` runtime
  (gVisor's user-space kernel) on top of every Standard hardening flag, so a
  container breakout must pierce gVisor's syscall filter before it reaches the
  host kernel. gVisor is Linux-only and installed separately; where it is not
  present the tier logs a warning and falls back to the Standard hardened
  container rather than silently claiming a protection it cannot give.

The ``docker run`` argument list is built and hardening-checked by pure
functions so it is unit-testable without Docker; the end-to-end container run is
exercised by the Docker-backed tests.
"""

from __future__ import annotations

import logging
import os
import sys
from collections.abc import Mapping, Sequence
from enum import Enum
from pathlib import Path

from finlexpurple.security.secrets import runtime_secret_flags
from finlexpurple.tools.sandbox import ToolResult, run_sandboxed

logger = logging.getLogger(__name__)

ISOLATION_ENV_VAR = "ISOLATION_TIER"
_DOCKER_SOCKET = "docker.sock"


class IsolationTier(str, Enum):
    """The three isolation tiers (decisions.md §27)."""

    NONE = "none"
    STANDARD = "standard"
    MAXIMUM = "maximum"


DEFAULT_TIER = IsolationTier.STANDARD


class IsolationError(RuntimeError):
    """A requested isolation tier could not be used as configured."""


class IsolationUnavailableError(IsolationError):
    """The Standard tier was requested but Docker is not available."""


class UnsafeIsolationArgsError(IsolationError):
    """A docker invocation was built that violates the hardening contract."""


def resolve_tier(env: Mapping[str, str] | None = None) -> IsolationTier:
    """Return the configured tier (default Standard); raise on an invalid value."""

    raw = (env or os.environ).get(ISOLATION_ENV_VAR, "").strip().lower()
    if not raw:
        return DEFAULT_TIER
    try:
        return IsolationTier(raw)
    except ValueError:
        choices = ", ".join(t.value for t in IsolationTier)
        raise IsolationError(
            f"Invalid {ISOLATION_ENV_VAR} {raw!r}; choose one of: {choices}."
        ) from None


def docker_available() -> bool:
    """Return True only if the Docker CLI is present and the daemon responds."""

    import shutil

    if shutil.which("docker") is None:
        return False
    try:
        # The docker CLI is our own trusted orchestration tool; it needs the host
        # environment (HOME, Docker context, DOCKER_* vars) to reach the daemon.
        result = run_sandboxed(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            timeout=15,
            env=dict(os.environ),
        )
    except OSError:
        return False
    return result.returncode == 0 and not result.timed_out and bool(result.stdout.strip())


def gvisor_available() -> bool:
    """True only if Docker exposes the gVisor (runsc) runtime.

    gVisor is Linux-only (its sandbox intercepts Linux syscalls), so this is
    always False on macOS/Windows hosts (decisions.md §18 item 11). On Linux it
    checks Docker's registered runtimes for ``runsc``.
    """

    if sys.platform != "linux" or not docker_available():
        return False
    try:
        result = run_sandboxed(
            ["docker", "info", "--format", "{{.Runtimes}}"], timeout=15, env=dict(os.environ)
        )
    except OSError:
        return False
    return result.returncode == 0 and "runsc" in result.stdout


def _container_user() -> str | None:
    """Run as the host's own uid:gid on POSIX (non-root, and able to write the output mount)."""

    if sys.platform == "win32":
        return None
    uid, gid = os.getuid(), os.getgid()
    # Never run as root inside the container; if the host user is root, drop to 'nobody'.
    if uid == 0:
        return "65534:65534"
    return f"{uid}:{gid}"


def build_docker_run_argv(
    image: str,
    inner_argv: Sequence[str],
    *,
    output_dir: Path,
    source_dir: Path | None = None,
    secret_env_names: Sequence[str] = (),
    memory: str = "1g",
    pids_limit: int = 256,
    runtime: str | None = None,
) -> list[str]:
    """Construct a hardened ``docker run`` argument list (no shell, no socket, no privilege).

    Only ``source_dir`` (read-only, at ``/work/src``) and ``output_dir``
    (writable, at ``/work/out``) cross the boundary. Network is disabled. Secret
    env vars are passed by name at runtime. ``runtime`` selects the container
    runtime — ``"runsc"`` for the Maximum (gVisor) tier — and is omitted for the
    Standard tier (Docker's default runtime). The result is validated by
    :func:`assert_hardened` before being returned.
    """

    argv: list[str] = ["docker", "run", "--rm"]
    if runtime is not None:
        argv += ["--runtime", runtime]  # e.g. gVisor's runsc (Maximum tier, §27)
    argv += [
        "--network", "none",            # no egress from the container by default
        "--read-only",                  # read-only root filesystem
        "--tmpfs", "/tmp",              # a small writable scratch, since root is ro
        "--cap-drop", "ALL",            # drop every Linux capability
        "--security-opt", "no-new-privileges",
        "--pids-limit", str(pids_limit),
        "--memory", memory,
        "-w", "/work",
    ]
    user = _container_user()
    if user is not None:
        argv += ["--user", user]
    argv += ["-v", f"{output_dir.resolve()}:/work/out"]          # the one writable mount
    if source_dir is not None:
        argv += ["-v", f"{source_dir.resolve()}:/work/src:ro"]   # source, read-only
    argv += runtime_secret_flags(secret_env_names)
    argv.append(image)
    argv += [str(a) for a in inner_argv]
    assert_hardened(argv)
    return argv


def assert_hardened(argv: Sequence[str]) -> None:
    """Raise :class:`UnsafeIsolationArgsError` if an argv breaks the hardening contract.

    Defense in depth: no ``--privileged``, no Docker-socket mount, no host
    network. Called on every built invocation and usable as a standalone guard.
    """

    tokens = [str(a) for a in argv]
    if "--privileged" in tokens:
        raise UnsafeIsolationArgsError("Refusing to run a privileged container.")
    for index, token in enumerate(tokens):
        if (
            token in {"-v", "--volume", "--mount"}
            and index + 1 < len(tokens)
            and _DOCKER_SOCKET in tokens[index + 1]
        ):
            raise UnsafeIsolationArgsError("Refusing to mount the Docker socket.")
        if token == "--network" and index + 1 < len(tokens) and tokens[index + 1] == "host":
            raise UnsafeIsolationArgsError("Refusing to share the host network namespace.")


def run_in_isolation(
    inner_argv: Sequence[str],
    *,
    tier: IsolationTier,
    output_dir: Path,
    image: str = "python:3.12-slim",
    source_dir: Path | None = None,
    secret_env_names: Sequence[str] = (),
    timeout: float = 600,
) -> ToolResult:
    """Run ``inner_argv`` under the given isolation tier.

    None runs on the host (after a warning); Standard runs inside the hardened
    container (refusing if Docker is unavailable); Maximum adds the gVisor
    (runsc) runtime where available and falls back to Standard with a warning
    where it is not (e.g. non-Linux hosts, or gVisor not installed).
    """

    if tier is IsolationTier.NONE:
        logger.warning(
            "Isolation tier is NONE: running on the host with no container boundary. "
            "This is less safe; Standard (Docker) is recommended."
        )
        output_dir.mkdir(parents=True, exist_ok=True)
        return run_sandboxed(inner_argv, timeout=timeout, cwd=output_dir)

    # Standard and Maximum both need Docker.
    if not docker_available():
        raise IsolationUnavailableError(
            f"Isolation tier is {tier.value.upper()} but Docker is not available. Install/start "
            "Docker, or choose the None tier (which runs on the host, with a warning)."
        )

    runtime: str | None = None
    if tier is IsolationTier.MAXIMUM:
        if gvisor_available():
            runtime = "runsc"  # gVisor: an extra filter between container and host kernel (§27)
        else:
            logger.warning(
                "Maximum tier requested but the gVisor (runsc) runtime is not available on this "
                "host (gVisor is Linux-only and installed separately; §27). Falling back to the "
                "Standard hardened container."
            )

    output_dir.mkdir(parents=True, exist_ok=True)
    argv = build_docker_run_argv(
        image,
        inner_argv,
        output_dir=output_dir,
        source_dir=source_dir,
        secret_env_names=secret_env_names,
        runtime=runtime,
    )
    # The docker CLI runs with the host environment (to reach the daemon and to
    # resolve -e NAME secret passthrough); the container itself gets the clean,
    # hardened environment defined by the argv above.
    return run_sandboxed(argv, timeout=timeout, env=dict(os.environ))
