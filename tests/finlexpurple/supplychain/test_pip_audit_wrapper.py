"""Phase 13: pip-audit output is parsed from real JSON, not paraphrased."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from finlexpurple.detectors.schema import Severity
from finlexpurple.supplychain.pip_audit_wrapper import (
    PipAuditError,
    parse_pip_audit_output,
    run_pip_audit,
)

# Newer pip-audit shape: {"dependencies": [...]}.
_WRAPPED = json.dumps(
    {
        "dependencies": [
            {
                "name": "flask",
                "version": "0.5",
                "vulns": [
                    {
                        "id": "PYSEC-2019-179",
                        "fix_versions": ["0.12.3"],
                        "description": "Flask before 0.12.3 ...",
                        "aliases": ["CVE-2019-1010083"],
                    }
                ],
            }
        ]
    }
)

# Older pip-audit shape: a top-level list.
_LIST = json.dumps(
    [{"name": "jinja2", "version": "2.10", "vulns": [{"id": "PYSEC-2019-217", "description": "x"}]}]
)


def test_parse_wrapped_shape() -> None:
    findings = parse_pip_audit_output(_WRAPPED)
    assert len(findings) == 1
    assert findings[0].vulnerability_class == "vulnerable_dependency"
    assert "PYSEC-2019-179" in findings[0].expected_signal
    assert "fixed in 0.12.3" in findings[0].expected_signal
    # pip-audit gives no severity; we default MEDIUM and never guess upward.
    assert findings[0].severity is Severity.MEDIUM


def test_parse_legacy_list_shape() -> None:
    findings = parse_pip_audit_output(_LIST)
    assert len(findings) == 1
    assert "PYSEC-2019-217" in findings[0].expected_signal


def test_snapshot_is_verbatim_vuln_object() -> None:
    f = parse_pip_audit_output(_WRAPPED)[0]
    snap = json.loads(f.response_snapshot or "{}")
    assert snap["id"] == "PYSEC-2019-179"
    assert snap["aliases"] == ["CVE-2019-1010083"]


def test_empty_and_invalid() -> None:
    assert parse_pip_audit_output("") == []
    with pytest.raises(PipAuditError):
        parse_pip_audit_output("nope {")
    with pytest.raises(PipAuditError):
        parse_pip_audit_output(json.dumps({"unexpected": 1}))


def test_run_with_injected_runner() -> None:
    def runner(args: object) -> tuple[int, str, str]:
        return (1, _WRAPPED, "")

    findings = run_pip_audit(Path("requirements.txt"), runner=runner)
    assert len(findings) == 1
