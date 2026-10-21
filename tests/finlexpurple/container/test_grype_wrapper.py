"""Phase 14: Grype output parsed from real JSON, not paraphrased."""

from __future__ import annotations

import json

import pytest

from finlexpurple.container.grype_wrapper import GrypeError, parse_grype_output, run_grype
from finlexpurple.detectors.schema import Severity

_GRYPE_JSON = json.dumps(
    {
        "matches": [
            {
                "vulnerability": {
                    "id": "CVE-2021-3711",
                    "severity": "High",
                    "description": "openssl SM2 decryption buffer overflow",
                },
                "artifact": {"name": "openssl", "version": "1.1.1d", "type": "deb"},
            }
        ]
    }
)


def test_parse_normalizes_and_maps_severity() -> None:
    findings = parse_grype_output(_GRYPE_JSON)
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert "CVE-2021-3711" in findings[0].expected_signal
    assert findings[0].payload == "openssl@1.1.1d:CVE-2021-3711"


def test_snapshot_is_verbatim_match_object() -> None:
    f = parse_grype_output(_GRYPE_JSON)[0]
    snap = json.loads(f.response_snapshot or "{}")
    assert snap["vulnerability"]["id"] == "CVE-2021-3711"


def test_empty_and_invalid() -> None:
    assert parse_grype_output("") == []
    assert parse_grype_output(json.dumps({"matches": []})) == []
    with pytest.raises(GrypeError):
        parse_grype_output(json.dumps({"no": "matches"}))


def test_run_with_injected_runner() -> None:
    assert len(run_grype("debian:10", runner=lambda args: (0, _GRYPE_JSON, ""))) == 1


def test_empty_output_is_an_error_not_clean() -> None:
    with pytest.raises(GrypeError):
        run_grype("img", runner=lambda args: (0, "", "grype: boom"))
