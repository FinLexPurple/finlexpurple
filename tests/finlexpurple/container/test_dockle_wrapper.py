"""Phase 14: Dockle output parsed from real JSON; only actionable levels count."""

from __future__ import annotations

import json

import pytest

from finlexpurple.container.dockle_wrapper import DockleError, parse_dockle_output, run_dockle
from finlexpurple.detectors.schema import Severity

_DOCKLE_JSON = json.dumps(
    {
        "summary": {"fatal": 1, "warn": 1, "info": 0, "pass": 5},
        "details": [
            {"code": "CIS-DI-0001", "title": "Create a user for the container",
             "level": "WARN", "alerts": ["Last user should not be root"]},
            {"code": "DKL-DI-0005", "title": "Clear apt-get caches", "level": "FATAL", "alerts": ["x"]},
            {"code": "CIS-DI-0005", "title": "Enable Content trust", "level": "PASS"},
            {"code": "CIS-DI-0006", "title": "healthcheck", "level": "SKIP"},
        ],
    }
)


def test_parse_only_actionable_levels_become_findings() -> None:
    findings = parse_dockle_output(_DOCKLE_JSON)
    # WARN + FATAL -> 2 findings; PASS and SKIP are dropped.
    assert len(findings) == 2
    codes = {f.payload for f in findings}
    assert codes == {"CIS-DI-0001", "DKL-DI-0005"}


def test_severity_mapping() -> None:
    by_code = {f.payload: f.severity for f in parse_dockle_output(_DOCKLE_JSON)}
    assert by_code["DKL-DI-0005"] is Severity.HIGH  # FATAL
    assert by_code["CIS-DI-0001"] is Severity.MEDIUM  # WARN


def test_invalid_and_run() -> None:
    with pytest.raises(DockleError):
        parse_dockle_output(json.dumps({"no": "details"}))
    assert len(run_dockle("img", runner=lambda args: (1, _DOCKLE_JSON, ""))) == 2
