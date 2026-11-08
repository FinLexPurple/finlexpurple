"""Unit 3.2: the CycloneDX 1.6 writer produces schema-valid output from the report's purls.

Validation is offline against the vendored official CycloneDX 1.6 JSON Schema. A report
with no purls (a pure web scan) yields a BOM with no components — never fabricated.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import jsonschema

from finlexpurple.detectors.schema import Finding, FindingStatus
from finlexpurple.reporting.aggregate import summarize
from finlexpurple.reporting.output_layout import write_report
from finlexpurple.reporting.writers.cyclonedx_writer import cyclonedx_document, render_cyclonedx
from finlexpurple.reporting.writers.json_writer import report_document

_SCHEMA_PATH = Path("src/finlexpurple/reporting/cyclonedx-1.6.schema.json")
_NOW = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)


def _schema() -> dict:
    return json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


def _dep_finding(verified: bool = False) -> Finding:
    f = Finding.new(vulnerability_class="vulnerable_dependency", method="SCA",
                    url="pkg:pypi/requests@2.0.0", payload="requests@2.0.0:CVE-x",
                    purl="pkg:pypi/requests@2.0.0", agent="supplychain")
    if verified:
        f.status = FindingStatus.VERIFIED
    return f


def _web_finding() -> Finding:
    return Finding.new(vulnerability_class="sqli", method="GET",
                       url="https://shop.invalid/search", payload="q='", agent="hunter")


def _document(findings: list[Finding]) -> dict:
    return report_document(target="https://shop.invalid", run_id="r1",
                           started_at="2026-11-08T00:00:00+00:00", generated_at="2026-11-08T00:00:00+00:00",
                           summary=summarize(findings), findings=findings)


def test_cyclonedx_validates_and_maps_components_from_purls() -> None:
    bom = cyclonedx_document(_document([_dep_finding()]))
    jsonschema.validate(bom, _schema())
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6"
    assert bom["serialNumber"].startswith("urn:uuid:")
    comp = bom["components"][0]
    assert comp["type"] == "library" and comp["name"] == "requests" and comp["version"] == "2.0.0"
    assert comp["purl"] == "pkg:pypi/requests@2.0.0"


def test_vex_only_for_verified_purl_findings() -> None:
    # Not verified -> no vulnerabilities section.
    assert "vulnerabilities" not in cyclonedx_document(_document([_dep_finding(verified=False)]))
    # Verified purl-bearing finding -> one exploitable VEX entry affecting the component.
    bom = cyclonedx_document(_document([_dep_finding(verified=True)]))
    jsonschema.validate(bom, _schema())
    vuln = bom["vulnerabilities"][0]
    assert vuln["analysis"]["state"] == "exploitable"
    assert vuln["affects"][0]["ref"] == "pkg:pypi/requests@2.0.0"


def test_no_purls_yields_no_components_not_fabricated() -> None:
    bom = cyclonedx_document(_document([_web_finding()]))
    jsonschema.validate(bom, _schema())
    assert bom["components"] == [] and "vulnerabilities" not in bom


def test_scan_writes_schema_valid_report_cyclonedx(tmp_path: Path) -> None:
    paths = write_report([_dep_finding()], target="https://shop.invalid", out_root=tmp_path,
                         now=_NOW, run_id="example-invalid-01617787-01M59ZNBK0ZKGNFAXEEP9EXSZ4",
                         formats=("cyclonedx",))
    assert paths.report_cyclonedx.exists()
    assert not paths.report_json.exists() and not paths.report_spdx.exists()
    jsonschema.validate(json.loads(paths.report_cyclonedx.read_text(encoding="utf-8")), _schema())


def test_render_is_deterministic() -> None:
    doc = _document([_dep_finding()])
    assert render_cyclonedx(doc) == render_cyclonedx(doc)
