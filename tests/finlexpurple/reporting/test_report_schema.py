"""Unit 1.3: report.json validates against the published schema, and stays in sync.

Three guarantees:
* a real ``report.json`` validates against the committed ``report.schema.json``;
* every ``Finding`` model field appears in the schema's finding properties, so
  the published contract cannot silently drift from the model;
* the report embeds no absolute local path (relocatable run directories).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import jsonschema

from finlexpurple.detectors.schema import Finding, FindingStatus
from finlexpurple.reporting.output_layout import write_report

_SCHEMA_PATH = Path("src/finlexpurple/reporting/report.schema.json")
_NOW = datetime(2026, 11, 3, 12, 0, 0, tzinfo=timezone.utc)
_RUN_ID = "example-invalid-01617787-01M59ZNBK0ZKGNFAXEEP9EXSZ4"


def _schema() -> dict:
    return json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


def _findings() -> list[Finding]:
    web = Finding.new(vulnerability_class="sqli", method="GET",
                      url="https://shop.invalid/search", payload="q='", agent="web")
    web.status = FindingStatus.VERIFIED
    web.verification_log = "SQL error reproduced."
    dep = Finding.new(vulnerability_class="vulnerable_dependency", method="SCA",
                      url="pkg:pypi/requests@2.0.0", payload="requests@2.0.0:CVE-x",
                      purl="pkg:pypi/requests@2.0.0", agent="supplychain")
    return [web, dep]


def test_report_json_validates_against_published_schema(tmp_path: Path) -> None:
    paths = write_report(_findings(), target="https://shop.invalid",
                         out_root=tmp_path, now=_NOW, run_id=_RUN_ID)
    report = json.loads(paths.report_json.read_text(encoding="utf-8"))
    jsonschema.validate(report, _schema())  # raises on any violation

    assert report["schema_version"] == 1
    assert report["run_id"] == _RUN_ID
    for finding in report["findings"]:
        assert finding["rule_id"]
        assert finding["location"]["route_template"]
        assert finding["severity"]
    dep = next(f for f in report["findings"] if f["vulnerability_class"] == "vulnerable_dependency")
    assert dep["purl"] == "pkg:pypi/requests@2.0.0"


def test_schema_covers_every_finding_model_field() -> None:
    """Drift guard: no Finding field may be missing from the published schema."""

    finding_props = set(_schema()["$defs"]["finding"]["properties"])
    model_fields = set(Finding.model_fields)
    missing = model_fields - finding_props
    assert not missing, f"report.schema.json is missing Finding fields: {sorted(missing)}"


def test_report_contains_no_absolute_local_path(tmp_path: Path) -> None:
    """Relocatable: the absolute run directory must not be embedded in report.json."""

    paths = write_report(_findings(), target="https://shop.invalid",
                         out_root=tmp_path, now=_NOW, run_id=_RUN_ID)
    text = paths.report_json.read_text(encoding="utf-8")
    assert str(tmp_path) not in text
