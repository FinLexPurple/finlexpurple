"""SARIF 2.1.0 report writer (Unit 3.1; ``--format sarif``).

A pure transform of the one ``report.json`` document (``json_writer.report_document``)
into SARIF 2.1.0, so the SARIF output can never drift from ``report.json``. The frozen
mappings (decisions.md; rule_catalog.py):

* ``result.ruleId`` ← the finding's ``rule_id`` (== its ``vulnerability_class``);
* ``tool.driver.rules`` ← the catalog records actually used in this report, each with
  its title/description/family and a ``defaultConfiguration.level`` from the frozen
  severity→level map; a result's ``ruleIndex`` points into this list;
* ``result.level`` ← ``rule_catalog.sarif_level(finding severity)`` (a per-result
  level, which SARIF lets override the rule default);
* ``partialFingerprints`` ← the versioned, host-independent ``fingerprint`` under the
  named key ``finlexpurpleFingerprint/v1``.

**Location (honest, no fabrication):** a result gets a ``physicalLocation`` **only when
the finding carries a real ``source_file`` (+ optional ``source_line``)** — never
invented. Otherwise it gets a ``logicalLocation`` naming the URL/route. GitHub code
scanning requires a *physical* location to **display** a result, so logical-location-only
results (every URL-based web/financial finding today) ingest and validate but will not
show in the code-scanning UI. We surface them truthfully rather than fake a file:line;
the url/method/route are also carried in the result's property bag for other consumers.
"""

from __future__ import annotations

import json
from typing import Any

from finlexpurple.detectors.schema import Severity
from finlexpurple.reporting.rule_catalog import sarif_level

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA_URI = "https://json.schemastore.org/sarif-2.1.0.json"
_INFORMATION_URI = "https://github.com/FinLexPurple/finlexpurple"

# The named key the versioned fingerprint is published under in partialFingerprints.
FINGERPRINT_KEY = "finlexpurpleFingerprint/v1"


def _driver_rules(used_rules: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Build ``tool.driver.rules`` (sorted by rule_id for determinism) + a rule_id→index map."""

    rules: list[dict[str, Any]] = []
    index_of: dict[str, int] = {}
    for rule_id in sorted(used_rules):
        record = used_rules[rule_id]
        index_of[rule_id] = len(rules)
        rules.append({
            "id": record["rule_id"],
            "name": record["title"],
            "shortDescription": {"text": record["title"]},
            "fullDescription": {"text": record["description"]},
            "defaultConfiguration": {
                "level": sarif_level(Severity(record["default_severity"])),
            },
            "properties": {"family": record["family"]},
        })
    return rules, index_of


def _result_location(location: dict[str, Any]) -> dict[str, Any]:
    """A SARIF location: a physicalLocation only when a real source file exists, else logical.

    Never fabricates a file:line. A url-only finding becomes a ``logicalLocation`` naming
    the route, with the url/method carried in the location's property bag.
    """

    source_file = location.get("source_file")
    if source_file:
        physical: dict[str, Any] = {"artifactLocation": {"uri": source_file}}
        source_line = location.get("source_line")
        if source_line is not None:
            physical["region"] = {"startLine": source_line}
        return {"physicalLocation": physical}
    route = location.get("route_template") or location.get("url") or ""
    return {
        "logicalLocations": [{"fullyQualifiedName": route, "kind": "route"}],
        "properties": {"url": location.get("url"), "method": location.get("method")},
    }


def _result(finding_doc: dict[str, Any], index_of: dict[str, int]) -> dict[str, Any]:
    """One SARIF result from a report-document finding."""

    rule_id = finding_doc["rule_id"]
    message = finding_doc.get("expected_signal") or rule_id
    result: dict[str, Any] = {
        "ruleId": rule_id,
        "level": sarif_level(Severity(finding_doc["severity"])),
        "message": {"text": message},
        "locations": [_result_location(finding_doc["location"])],
        "partialFingerprints": {FINGERPRINT_KEY: finding_doc["fingerprint"]},
        "properties": {
            "status": finding_doc["status"],
            "finding_id": finding_doc["finding_id"],
            "vulnerability_class": finding_doc["vulnerability_class"],
        },
    }
    if rule_id in index_of:
        result["ruleIndex"] = index_of[rule_id]
    return result


def sarif_document(document: dict[str, Any]) -> dict[str, Any]:
    """Transform the report document (``json_writer.report_document``) into a SARIF 2.1.0 dict."""

    rules, index_of = _driver_rules(document.get("rules", {}))
    tool_version = document.get("tool", {}).get("version", "")
    results = [_result(finding_doc, index_of) for finding_doc in document.get("findings", [])]
    return {
        "$schema": SARIF_SCHEMA_URI,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "finlexpurple",
                        "version": tool_version,
                        "informationUri": _INFORMATION_URI,
                        "rules": rules,
                    }
                },
                "results": results,
            }
        ],
    }


def render_sarif(document: dict[str, Any]) -> str:
    """Render the report document as SARIF 2.1.0 JSON text."""

    return json.dumps(sarif_document(document), indent=2, ensure_ascii=True, sort_keys=True) + "\n"
