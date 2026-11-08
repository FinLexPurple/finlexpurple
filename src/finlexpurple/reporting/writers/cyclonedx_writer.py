"""CycloneDX 1.6 SBOM writer (Unit 3.2; ``--format cyclonedx``).

A pure transform of the one ``report.json`` document into a CycloneDX 1.6 BOM, so it
can never drift from ``report.json``. It describes the **dependency surface** the report
carries:

* ``components[]`` — one ``library`` component per **distinct ``purl``** on a finding
  (name/version parsed from the purl; the purl carried verbatim). Purls are set only when
  a detector has a real package coordinate, so nothing is fabricated; a report with no
  purls (e.g. a pure web scan) yields a BOM with no components.
* ``vulnerabilities[]`` (the CycloneDX **VEX** section) — one entry per finding that
  carries a purl **and** is ``verified``, with ``analysis.state = "exploitable"`` and an
  ``affects[].ref`` pointing at the affected component. Supply-chain findings normally
  stay ``reported`` (no replay), so this section is usually empty — emitted truthfully,
  never invented.

The ``serialNumber`` is a deterministic ``urn:uuid`` derived from the run id, so the same
run renders a stable BOM.
"""

from __future__ import annotations

import json
import uuid
from typing import Any

from finlexpurple.reporting.writers.sbom_common import (
    distinct_purls,
    parse_purl,
    verified_purl_findings,
)

CYCLONEDX_SPEC_VERSION = "1.6"
CYCLONEDX_SCHEMA_URI = "http://cyclonedx.org/schema/bom-1.6.schema.json"
# A fixed namespace so the run id maps to a stable urn:uuid serial number.
_SERIAL_NAMESPACE = uuid.UUID("6f6b1b1e-6f0a-5a5a-9a9a-f1e2d3c4b5a6")


def _serial_number(run_id: str) -> str:
    """A deterministic ``urn:uuid:…`` BOM serial number for this run."""

    return f"urn:uuid:{uuid.uuid5(_SERIAL_NAMESPACE, run_id)}"


def _component(purl: str) -> dict[str, Any]:
    """One CycloneDX ``library`` component from a purl (version omitted when absent)."""

    _purl_type, name, version = parse_purl(purl)
    component: dict[str, Any] = {
        "type": "library",
        "name": name or purl,
        "bom-ref": purl,
        "purl": purl,
    }
    if version:
        component["version"] = version
    return component


def _vulnerability(finding: dict[str, Any]) -> dict[str, Any]:
    """A CycloneDX VEX entry for a verified, purl-bearing finding (state: exploitable)."""

    vuln: dict[str, Any] = {
        "bom-ref": finding["finding_id"],
        "id": finding["rule_id"],
        "source": {"name": "finlexpurple"},
        "analysis": {"state": "exploitable"},
        "affects": [{"ref": finding["purl"]}],
    }
    detail = finding.get("expected_signal")
    if detail:
        vuln["description"] = detail
    return vuln


def cyclonedx_document(document: dict[str, Any]) -> dict[str, Any]:
    """Transform the report document into a CycloneDX 1.6 BOM dict."""

    tool_version = document.get("tool", {}).get("version", "")
    bom: dict[str, Any] = {
        "$schema": CYCLONEDX_SCHEMA_URI,
        "bomFormat": "CycloneDX",
        "specVersion": CYCLONEDX_SPEC_VERSION,
        "serialNumber": _serial_number(document.get("run_id", "")),
        "version": 1,
        "metadata": {
            "timestamp": document.get("generated_at"),
            "tools": {
                "components": [
                    {"type": "application", "name": "finlexpurple", "version": tool_version}
                ]
            },
        },
        "components": [_component(purl) for purl in distinct_purls(document)],
    }
    vulnerabilities = [_vulnerability(f) for f in verified_purl_findings(document)]
    if vulnerabilities:
        bom["vulnerabilities"] = vulnerabilities
    return bom


def render_cyclonedx(document: dict[str, Any]) -> str:
    """Render the report document as a CycloneDX 1.6 BOM (JSON text)."""

    return json.dumps(cyclonedx_document(document), indent=2, ensure_ascii=True, sort_keys=True) + "\n"
