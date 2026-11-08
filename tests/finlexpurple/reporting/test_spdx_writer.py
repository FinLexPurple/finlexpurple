"""Unit 3.2: the SPDX 2.3 writer produces schema-valid output from the report's purls.

Validation is offline against the vendored official SPDX 2.3 JSON Schema. A report with
no purls (a pure web scan) yields a document with no packages — never fabricated.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import jsonschema

from finlexpurple.detectors.schema import Finding
from finlexpurple.reporting.aggregate import summarize
from finlexpurple.reporting.output_layout import write_report
from finlexpurple.reporting.writers.json_writer import report_document
from finlexpurple.reporting.writers.spdx_writer import render_spdx, spdx_document

_SCHEMA_PATH = Path("src/finlexpurple/reporting/spdx-2.3.schema.json")
_NOW = datetime(2026, 11, 8, 12, 0, 0, tzinfo=timezone.utc)


def _schema() -> dict:
    return json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


def _dep_finding() -> Finding:
    return Finding.new(vulnerability_class="vulnerable_dependency", method="SCA",
                       url="pkg:pypi/requests@2.0.0", payload="requests@2.0.0:CVE-x",
                       purl="pkg:pypi/requests@2.0.0", agent="supplychain")


def _web_finding() -> Finding:
    return Finding.new(vulnerability_class="sqli", method="GET",
                       url="https://shop.invalid/search", payload="q='", agent="hunter")


def _document(findings: list[Finding]) -> dict:
    return report_document(target="https://shop.invalid", run_id="r1",
                           started_at="2026-11-08T00:00:00+00:00", generated_at="2026-11-08T12:30:45+00:00",
                           summary=summarize(findings), findings=findings)


def test_spdx_validates_and_maps_packages_from_purls() -> None:
    doc = spdx_document(_document([_dep_finding()]))
    jsonschema.validate(doc, _schema())
    assert doc["spdxVersion"] == "SPDX-2.3" and doc["SPDXID"] == "SPDXRef-DOCUMENT"
    assert doc["dataLicense"] == "CC0-1.0"
    # a canonical SPDX timestamp (trailing Z, second precision).
    assert doc["creationInfo"]["created"] == "2026-11-08T12:30:45Z"
    assert doc["creationInfo"]["creators"][0].startswith("Tool: finlexpurple-")
    pkg = doc["packages"][0]
    assert pkg["name"] == "requests" and pkg["versionInfo"] == "2.0.0"
    ref = pkg["externalRefs"][0]
    assert ref["referenceCategory"] == "PACKAGE-MANAGER" and ref["referenceType"] == "purl"
    assert ref["referenceLocator"] == "pkg:pypi/requests@2.0.0"


def test_document_describes_each_package() -> None:
    doc = spdx_document(_document([_dep_finding()]))
    rel = doc["relationships"][0]
    assert rel["spdxElementId"] == "SPDXRef-DOCUMENT" and rel["relationshipType"] == "DESCRIBES"
    assert rel["relatedSpdxElement"] == doc["packages"][0]["SPDXID"]


def test_no_purls_yields_no_packages_not_fabricated() -> None:
    doc = spdx_document(_document([_web_finding()]))
    jsonschema.validate(doc, _schema())
    assert doc["packages"] == [] and doc["relationships"] == []


def test_scan_writes_schema_valid_report_spdx(tmp_path: Path) -> None:
    paths = write_report([_dep_finding()], target="https://shop.invalid", out_root=tmp_path,
                         now=_NOW, run_id="example-invalid-01617787-01M59ZNBK0ZKGNFAXEEP9EXSZ4",
                         formats=("spdx",))
    assert paths.report_spdx.exists()
    assert not paths.report_json.exists() and not paths.report_cyclonedx.exists()
    jsonschema.validate(json.loads(paths.report_spdx.read_text(encoding="utf-8")), _schema())


def test_render_is_deterministic() -> None:
    doc = _document([_dep_finding()])
    assert render_spdx(doc) == render_spdx(doc)
