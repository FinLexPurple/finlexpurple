"""Phase 7 acceptance items 3 & 4: tiered container isolation (decisions.md §27).

Pure tests cover tier resolution, the hardened docker-run argv construction, the
hardening guard, and the None-tier host path. The Docker-backed test exercises
the Standard-tier boundary end to end and is skipped where Docker is absent.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

from finlexpurple.security import isolation
from finlexpurple.security.isolation import (
    DEFAULT_TIER,
    IsolationError,
    IsolationTier,
    IsolationUnavailableError,
    UnsafeIsolationArgsError,
    assert_hardened,
    build_docker_run_argv,
    resolve_tier,
    run_in_isolation,
)


def test_resolve_tier_defaults_to_standard_and_validates(tmp_path) -> None:
    assert resolve_tier({}) is DEFAULT_TIER is IsolationTier.STANDARD
    assert resolve_tier({"ISOLATION_TIER": "none"}) is IsolationTier.NONE
    assert resolve_tier({"ISOLATION_TIER": "MAXIMUM"}) is IsolationTier.MAXIMUM
    with pytest.raises(IsolationError, match="Invalid"):
        resolve_tier({"ISOLATION_TIER": "ultra"})


def test_docker_run_argv_is_hardened(tmp_path: Path) -> None:
    argv = build_docker_run_argv(
        "python:3.12-slim",
        ["python", "-c", "print('x')"],
        output_dir=tmp_path / "out",
        source_dir=tmp_path / "src",
        secret_env_names=["ANTHROPIC_API_KEY"],
    )
    joined = " ".join(argv)
    assert "--read-only" in argv
    assert argv.count("--network") == 1 and "none" in argv
    assert "--cap-drop" in argv and "ALL" in argv
    assert "no-new-privileges" in joined
    assert "--privileged" not in argv
    assert "docker.sock" not in joined
    # Source read-only, output writable, secret passed by name only.
    assert f"{(tmp_path / 'src').resolve()}:/work/src:ro" in argv
    assert f"{(tmp_path / 'out').resolve()}:/work/out" in argv
    assert "-e" in argv and "ANTHROPIC_API_KEY" in argv
    assert "ANTHROPIC_API_KEY=" not in joined  # value never embedded


def test_assert_hardened_rejects_unsafe_invocations() -> None:
    with pytest.raises(UnsafeIsolationArgsError, match="privileged"):
        assert_hardened(["docker", "run", "--privileged", "img"])
    with pytest.raises(UnsafeIsolationArgsError, match="Docker socket"):
        assert_hardened(["docker", "run", "-v", "/var/run/docker.sock:/var/run/docker.sock", "img"])
    with pytest.raises(UnsafeIsolationArgsError, match="host network"):
        assert_hardened(["docker", "run", "--network", "host", "img"])


def test_maximum_tier_is_deferred_to_phase_20(tmp_path: Path) -> None:
    with pytest.raises(IsolationError, match="Phase 20"):
        run_in_isolation(["python", "-c", "pass"], tier=IsolationTier.MAXIMUM, output_dir=tmp_path)


def test_standard_refuses_when_docker_unavailable(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setattr(isolation, "docker_available", lambda: False)
    with pytest.raises(IsolationUnavailableError, match="Docker is not available"):
        run_in_isolation(["python", "-c", "pass"], tier=IsolationTier.STANDARD, output_dir=tmp_path)


def test_none_tier_runs_on_host(tmp_path: Path) -> None:
    result = run_in_isolation(
        [sys.executable, "-c", "print('on-host')"],
        tier=IsolationTier.NONE,
        output_dir=tmp_path / "out",
    )
    assert result.returncode == 0 and "on-host" in result.stdout


# ----- Docker-backed end-to-end boundary test (skipped where Docker is absent) -----

_BOUNDARY_SCRIPT = (
    "import json, os, socket\n"
    "r = {'uid': os.getuid()}\n"
    "try:\n"
    "    open('/root_probe', 'w').close(); r['root_write'] = 'OK'\n"
    "except OSError:\n"
    "    r['root_write'] = 'DENIED'\n"
    "try:\n"
    "    open('/work/out/ok.txt', 'w').write('findings'); r['out_write'] = 'OK'\n"
    "except OSError:\n"
    "    r['out_write'] = 'DENIED'\n"
    "try:\n"
    "    open('/work/src/probe', 'w').close(); r['src_write'] = 'OK'\n"
    "except OSError:\n"
    "    r['src_write'] = 'DENIED'\n"
    "try:\n"
    "    socket.create_connection(('1.1.1.1', 53), timeout=3); r['net'] = 'OK'\n"
    "except OSError:\n"
    "    r['net'] = 'DENIED'\n"
    "print(json.dumps(r))\n"
)


@pytest.mark.skipif(not isolation.docker_available(), reason="Docker not available")
def test_standard_tier_boundary_end_to_end(tmp_path: Path) -> None:
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    (source_dir / "app.py").write_text("print('hello')\n", encoding="utf-8")
    output_dir = tmp_path / "out"

    result = run_in_isolation(
        ["python", "-c", _BOUNDARY_SCRIPT],
        tier=IsolationTier.STANDARD,
        output_dir=output_dir,
        source_dir=source_dir,
        timeout=120,
    )

    assert result.returncode == 0, f"stdout={result.stdout!r} stderr={result.stderr!r}"
    report = json.loads(result.stdout.strip().splitlines()[-1])
    assert report["uid"] != 0            # non-root inside the container
    assert report["root_write"] == "DENIED"   # read-only root filesystem
    assert report["src_write"] == "DENIED"    # source mounted read-only
    assert report["net"] == "DENIED"          # no network egress
    assert report["out_write"] == "OK"        # the one writable mount
    # Findings/evidence crossed back out to the host output dir.
    assert (output_dir / "ok.txt").read_text(encoding="utf-8") == "findings"
