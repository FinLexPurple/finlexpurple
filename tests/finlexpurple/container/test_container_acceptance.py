"""Phase 14 §5a acceptance: a deliberately bad container is fully flagged.

A project with a Dockerfile that runs as root on a known-vulnerable base and a
docker-compose file that mounts the host Docker socket and runs privileged.
Every wrapped tool's output is parsed/normalized and the escape/exposed-socket
checks produce schema findings; the feed-staleness context is reported and
online vs offline is recorded.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from finlexpurple.container.scanner import ContainerResult, scan_container
from finlexpurple.supplychain.mode import ScanMode

# Real scanner JSON shapes (the binaries are not installed here).
_TRIVY = json.dumps({"Results": [{"Target": "vulnbase:1.0", "Vulnerabilities": [
    {"VulnerabilityID": "CVE-2021-3711", "PkgName": "openssl", "InstalledVersion": "1.1.1d",
     "Severity": "CRITICAL", "Title": "SM2 buffer overflow"}]}]})
_GRYPE = json.dumps({"matches": [{"vulnerability": {"id": "CVE-2021-3711", "severity": "Critical"},
                                  "artifact": {"name": "openssl", "version": "1.1.1d"}}]})
_DOCKLE = json.dumps({"details": [{"code": "CIS-DI-0001", "title": "Create a user", "level": "FATAL"}]})
_HADO = json.dumps([{"line": 1, "code": "DL3002", "message": "Last USER should not be root",
                     "level": "warning", "file": "Dockerfile"}])


@pytest.fixture
def bad_project(tmp_path: Path) -> Path:
    (tmp_path / "Dockerfile").write_text(
        "FROM vulnbase:1.0\nRUN apt-get update\n",  # runs as root, vulnerable base
        encoding="utf-8",
    )
    (tmp_path / "docker-compose.yml").write_text(
        "services:\n"
        "  web:\n"
        "    privileged: true\n"
        "    volumes:\n"
        "      - /var/run/docker.sock:/var/run/docker.sock\n",
        encoding="utf-8",
    )
    return tmp_path


def _run(project: Path, mode: ScanMode) -> ContainerResult:
    return scan_container(
        image="vulnbase:1.0",
        project_path=project,
        mode=mode,
        trivy_runner=lambda a: (0, _TRIVY, ""),
        grype_runner=lambda a: (0, _GRYPE, ""),
        dockle_runner=lambda a: (1, _DOCKLE, ""),
        hadolint_runner=lambda a: (1, _HADO, ""),
    )


def test_every_tool_and_every_escape_check_produces_findings(bad_project: Path) -> None:
    result = _run(bad_project, ScanMode.ONLINE)
    classes = {f.vulnerability_class for f in result.findings}
    # Wrapped scanners, normalized (no prose passed through — snapshots are JSON objects):
    assert "container_image_vuln" in classes  # Trivy + Grype
    assert "container_best_practice" in classes  # Dockle
    assert "dockerfile_lint" in classes  # hadolint
    # Original escape / exposed-socket checks:
    assert "container_runs_as_root" in classes
    assert "privileged_container" in classes
    assert "exposed_docker_socket" in classes
    assert result.warnings == []  # all tools supplied via injected runners


def test_offline_reports_feed_staleness(bad_project: Path) -> None:
    result = _run(bad_project, ScanMode.OFFLINE)
    assert result.mode is ScanMode.OFFLINE
    assert "offline feed last refreshed" in result.feed_status.summary()
    # The image vulnerabilities are still found from the last-refreshed feed.
    assert any(f.vulnerability_class == "container_image_vuln" for f in result.findings)
