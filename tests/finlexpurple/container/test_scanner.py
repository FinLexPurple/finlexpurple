"""Phase 14: the container aggregator wiring and honest tool-missing warnings."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from finlexpurple.container.scanner import scan_container
from finlexpurple.supplychain.mode import ScanMode

_TRIVY = json.dumps({"Results": [{"Target": "img", "Vulnerabilities": [
    {"VulnerabilityID": "CVE-1", "PkgName": "openssl", "InstalledVersion": "1", "Severity": "HIGH", "Title": "t"}]}]})
_GRYPE = json.dumps({"matches": [{"vulnerability": {"id": "CVE-2", "severity": "High"},
                                  "artifact": {"name": "openssl", "version": "1"}}]})
_DOCKLE = json.dumps({"details": [{"code": "CIS-DI-0001", "title": "user", "level": "WARN"}]})
_HADO = json.dumps([{"line": 1, "code": "DL3006", "message": "tag", "level": "error", "file": "Dockerfile"}])


def test_image_scan_aggregates_all_three_image_tools() -> None:
    result = scan_container(
        image="badimage:latest",
        trivy_runner=lambda a: (0, _TRIVY, ""),
        grype_runner=lambda a: (0, _GRYPE, ""),
        dockle_runner=lambda a: (1, _DOCKLE, ""),
    )
    classes = {f.vulnerability_class for f in result.findings}
    assert "container_image_vuln" in classes
    assert "container_best_practice" in classes
    assert result.warnings == []


def test_project_scan_lints_and_checks_escape(tmp_path: Path) -> None:
    (tmp_path / "Dockerfile").write_text("FROM debian:10\nRUN echo hi\n", encoding="utf-8")
    result = scan_container(
        project_path=tmp_path,
        hadolint_runner=lambda a: (1, _HADO, ""),
    )
    classes = {f.vulnerability_class for f in result.findings}
    assert "dockerfile_lint" in classes  # hadolint
    assert "container_runs_as_root" in classes  # original escape check


def test_warns_when_tools_absent(monkeypatch: pytest.MonkeyPatch) -> None:
    # Force the "tool absent" path deterministically, independent of the machine.
    monkeypatch.setattr(shutil, "which", lambda name: None)
    result = scan_container(image="img", mode=ScanMode.OFFLINE)
    assert any("trivy not installed" in w for w in result.warnings)
    assert any("grype not installed" in w for w in result.warnings)
    assert result.feed_status is not None


def test_runtime_config_is_checked_directly() -> None:
    result = scan_container(runtime_config={"HostConfig": {"Privileged": True}})
    assert any(f.vulnerability_class == "privileged_container" for f in result.findings)
