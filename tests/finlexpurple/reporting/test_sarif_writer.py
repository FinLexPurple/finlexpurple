"""Unit 3.1: the SARIF 2.1.0 writer produces schema-valid output and the frozen mappings.

Validation is offline against the vendored official OASIS SARIF 2.1.0 JSON Schema
(src/finlexpurple/reporting/sarif-2.1.0.schema.json) — the tool never fetches at runtime.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import jsonschema

from finlexpurple.detectors.schema import Finding, FindingStatus, Severity
from finlexpurple.reporting.aggregate import summarize
from finlexpurple.reporting.output_layout import write_report
from finlexpurple.reporting.rule_catalog import sarif_level
from finlexpurple.reporting.writers.json_writer import report_document
from finlexpurple.reporting.writers.sarif_writer import (
    FINGERPRINT_KEY,
    render_sarif,
    sarif_document,
)

_SARIF_SCHEMA_PATH = Path("src/finlexpurple/reporting/sarif-2.1.0.schema.json")
_NOW = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)


def _sarif_schema() -> dict:
    return json.loads(_SARIF_SCHEMA_PATH.read_text(encoding="utf-8"))


def _url_finding() -> Finding:
    f = Finding.new(vulnerability_class="refund_abuse", method="POST",
                    url="https://shop.invalid/orders/ord-refund-0001/refund",
                    payload="amount=999.99", agent="cashier")
    f.severity = Severity.HIGH
    f.status = FindingStatus.VERIFIED
    return f


def _source_finding() -> Finding:
    f = Finding.new(vulnerability_class="sqli", method="GET",
                    url="https://shop.invalid/search", payload="q='", agent="hunter")
    f.source_file, f.source_line = "app/search.py", 42
    return f


def _document(findings: list[Finding]) -> dict:
    return report_document(
        target="https://shop.invalid", run_id="r1",
        started_at="2026-11-08T00:00:00+00:00", generated_at="2026-11-08T00:00:00+00:00",
        summary=summarize(findings), findings=findings,
    )


def test_sarif_output_validates_against_the_official_schema() -> None:
    doc = sarif_document(_document([_url_finding(), _source_finding()]))
    jsonschema.validate(doc, _sarif_schema())  # raises on any violation
    assert doc["version"] == "2.1.0" and len(doc["runs"]) == 1


def test_rule_id_level_and_fingerprint_mappings() -> None:
    doc = sarif_document(_document([_url_finding()]))
    result = doc["runs"][0]["results"][0]
    assert result["ruleId"] == "refund_abuse"
    # level <- the finding's own severity (HIGH -> error), per the frozen map.
    assert result["level"] == sarif_level(Severity.HIGH) == "error"
    # the versioned, host-independent fingerprint under the named key.
    assert set(result["partialFingerprints"]) == {FINGERPRINT_KEY}
    assert result["partialFingerprints"][FINGERPRINT_KEY].startswith("flpfp1:sha256:")


def test_driver_rules_carry_catalog_metadata_and_ruleindex_matches() -> None:
    doc = sarif_document(_document([_url_finding(), _source_finding()]))
    driver = doc["runs"][0]["tool"]["driver"]
    assert driver["name"] == "finlexpurple"
    rules = driver["rules"]
    by_id = {r["id"]: r for r in rules}
    assert {"refund_abuse", "sqli"} <= set(by_id)
    # a real catalog title/description/family, not the unknown fallback.
    assert by_id["refund_abuse"]["properties"]["family"] == "financial"
    assert "no catalog entry" not in by_id["refund_abuse"]["fullDescription"]["text"]
    # every result's ruleIndex points at its own rule in driver.rules.
    for result in doc["runs"][0]["results"]:
        assert rules[result["ruleIndex"]]["id"] == result["ruleId"]


def test_physical_location_only_with_a_real_source_file_else_logical() -> None:
    doc = sarif_document(_document([_url_finding(), _source_finding()]))
    by_rule = {r["ruleId"]: r for r in doc["runs"][0]["results"]}
    # url-only finding -> logicalLocation (no fabricated file:line), route carried.
    url_loc = by_rule["refund_abuse"]["locations"][0]
    assert "physicalLocation" not in url_loc
    assert url_loc["logicalLocations"][0]["fullyQualifiedName"] == "/orders/ord-refund-0001/refund"
    # finding with a real source file -> physicalLocation with the file + line.
    src_loc = by_rule["sqli"]["locations"][0]
    assert src_loc["physicalLocation"]["artifactLocation"]["uri"] == "app/search.py"
    assert src_loc["physicalLocation"]["region"]["startLine"] == 42


def test_scan_writes_schema_valid_report_sarif(tmp_path: Path) -> None:
    paths = write_report(
        [_url_finding(), _source_finding()], target="https://shop.invalid",
        out_root=tmp_path, now=_NOW, run_id="example-invalid-01617787-01M59ZNBK0ZKGNFAXEEP9EXSZ4",
        formats=("sarif",),
    )
    assert paths.report_sarif.exists()
    # Only SARIF requested -> no report.json / report.md written.
    assert not paths.report_json.exists() and not paths.report_md.exists()
    jsonschema.validate(json.loads(paths.report_sarif.read_text(encoding="utf-8")), _sarif_schema())


def test_render_sarif_is_deterministic_text() -> None:
    doc = _document([_url_finding(), _source_finding()])
    assert render_sarif(doc) == render_sarif(doc)
