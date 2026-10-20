"""Phase 14: Trivy output parsed from real JSON, not paraphrased."""

from __future__ import annotations

import json

import pytest

from finlexpurple.container.trivy_wrapper import TrivyError, parse_trivy_output, run_trivy
from finlexpurple.detectors.schema import Severity

_TRIVY_JSON = json.dumps(
    {
        "SchemaVersion": 2,
        "ArtifactName": "debian:10",
        "Results": [
            {
                "Target": "debian:10 (debian 10)",
                "Class": "os-pkgs",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2021-3711",
                        "PkgName": "openssl",
                        "InstalledVersion": "1.1.1d",
                        "FixedVersion": "1.1.1k",
                        "Severity": "CRITICAL",
                        "Title": "openssl: SM2 Decryption Buffer Overflow",
                    }
                ],
            },
            {"Target": "x", "Class": "os-pkgs", "Vulnerabilities": None},
        ],
    }
)


def test_parse_normalizes_and_maps_severity() -> None:
    findings = parse_trivy_output(_TRIVY_JSON)
    assert len(findings) == 1
    f = findings[0]
    assert f.vulnerability_class == "container_image_vuln"
    assert f.severity is Severity.CRITICAL
    assert "CVE-2021-3711" in f.expected_signal


def test_snapshot_is_verbatim_vuln_object() -> None:
    f = parse_trivy_output(_TRIVY_JSON)[0]
    snap = json.loads(f.response_snapshot or "{}")
    assert snap["VulnerabilityID"] == "CVE-2021-3711"
    assert snap["FixedVersion"] == "1.1.1k"


def test_empty_and_invalid() -> None:
    assert parse_trivy_output("") == []
    with pytest.raises(TrivyError):
        parse_trivy_output("nope {")
    with pytest.raises(TrivyError):
        parse_trivy_output(json.dumps({"no": "results"}))


def test_run_with_injected_runner() -> None:
    findings = run_trivy("debian:10", runner=lambda args: (0, _TRIVY_JSON, ""))
    assert len(findings) == 1


def test_run_error_exit_raises() -> None:
    with pytest.raises(TrivyError):
        run_trivy("debian:10", runner=lambda args: (2, "", "trivy: fatal"))
