"""Phase 13: OSV-Scanner output is parsed from real JSON, not paraphrased."""

from __future__ import annotations

import json

import pytest

from finlexpurple.detectors.schema import Severity
from finlexpurple.supplychain.osv_wrapper import (
    OSVScannerError,
    parse_osv_output,
    run_osv_scanner,
)

# A real osv-scanner --format json shape (trimmed to the fields we read).
_OSV_JSON = json.dumps(
    {
        "results": [
            {
                "source": {"path": "/proj/requirements.txt", "type": "lockfile"},
                "packages": [
                    {
                        "package": {"name": "requests", "version": "2.19.0", "ecosystem": "PyPI"},
                        "vulnerabilities": [
                            {
                                "id": "GHSA-x84v-xcm2-53pg",
                                "summary": "Insufficiently Protected Credentials in requests",
                                "aliases": ["CVE-2018-18074"],
                                "database_specific": {"severity": "HIGH"},
                            }
                        ],
                        "groups": [{"ids": ["GHSA-x84v-xcm2-53pg"], "max_severity": "7.5"}],
                    }
                ],
            }
        ]
    }
)


def test_parse_normalizes_vulnerabilities_to_findings() -> None:
    findings = parse_osv_output(_OSV_JSON)
    assert len(findings) == 1
    f = findings[0]
    assert f.vulnerability_class == "vulnerable_dependency"
    assert f.severity is Severity.HIGH
    assert "GHSA-x84v-xcm2-53pg" in f.expected_signal


def test_evidence_snapshot_is_the_tools_verbatim_object_not_prose() -> None:
    f = parse_osv_output(_OSV_JSON)[0]
    # The snapshot is the tool's own JSON object, re-serialized — not a paraphrase.
    snapshot = json.loads(f.response_snapshot or "{}")
    assert snapshot["id"] == "GHSA-x84v-xcm2-53pg"
    assert snapshot["aliases"] == ["CVE-2018-18074"]


def test_empty_output_is_no_findings() -> None:
    assert parse_osv_output("") == []
    assert parse_osv_output(json.dumps({"results": []})) == []


def test_invalid_json_raises() -> None:
    with pytest.raises(OSVScannerError):
        parse_osv_output("not json {")


def test_unexpected_shape_raises_rather_than_guessing() -> None:
    with pytest.raises(OSVScannerError):
        parse_osv_output(json.dumps({"unexpected": True}))


def test_run_with_injected_runner_exit_1_means_vulns_found() -> None:
    def runner(args: object) -> tuple[int, str, str]:
        return (1, _OSV_JSON, "")

    findings = run_osv_scanner(project_path=__import__("pathlib").Path("."), runner=runner)
    assert len(findings) == 1


def test_run_with_injected_runner_error_exit_raises() -> None:
    def runner(args: object) -> tuple[int, str, str]:
        return (127, "", "osv-scanner: command failed")

    with pytest.raises(OSVScannerError):
        run_osv_scanner(project_path=__import__("pathlib").Path("."), runner=runner)


def test_project_path_is_passed_absolute() -> None:
    # Regression: the sandbox runs in an isolated cwd; a relative path would make
    # the scan silently find nothing, so the wrapper must resolve it.
    from pathlib import Path

    captured: dict[str, list[str]] = {}

    def runner(args: object) -> tuple[int, str, str]:
        captured["args"] = [str(a) for a in args]  # type: ignore[arg-type]
        return (0, "", "")

    run_osv_scanner(project_path=Path("."), runner=runner)
    assert str(Path.cwd()) in captured["args"]  # Path(".").resolve() == cwd
