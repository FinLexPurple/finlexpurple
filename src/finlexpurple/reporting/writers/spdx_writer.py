"""SPDX 2.3 SBOM writer (Unit 3.2; ``--format spdx``).

A pure transform of the one ``report.json`` document into an SPDX 2.3 document (the
version consumers read today), so it can never drift from ``report.json``. It describes
the **dependency surface** the report carries:

* ``packages[]`` — one package per **distinct ``purl``** on a finding (name/version parsed
  from the purl; the purl carried as a ``PACKAGE-MANAGER`` ``externalRef`` of type
  ``purl``). Purls are set only when a detector has a real package coordinate, so nothing
  is fabricated; a report with no purls (e.g. a pure web scan) yields a document whose
  only relationship is the document describing nothing.
* ``relationships[]`` — ``SPDXRef-DOCUMENT DESCRIBES`` each package.

Downstream consumers read SBOMs, not exploit verdicts, so this document intentionally
carries the component surface only; the exploit/VEX view lives in the CycloneDX writer.
"""

from __future__ import annotations

import json
import uuid
from datetime import datetime
from typing import Any

from finlexpurple.reporting.writers.sbom_common import distinct_purls, parse_purl

SPDX_VERSION = "SPDX-2.3"
_DATA_LICENSE = "CC0-1.0"
_DOC_NAMESPACE_BASE = "https://finlexpurple.invalid/spdx"
# A fixed namespace so the run id maps to a stable documentNamespace uuid.
_NAMESPACE_UUID = uuid.UUID("5c4d3e2f-1a0b-5c6d-8e9f-0a1b2c3d4e5f")


def _spdx_timestamp(generated_at: str | None) -> str:
    """SPDX wants ``YYYY-MM-DDThh:mm:ssZ`` (UTC, second precision, trailing Z)."""

    if not generated_at:
        return "1970-01-01T00:00:00Z"
    try:
        moment = datetime.fromisoformat(generated_at)
    except ValueError:
        return "1970-01-01T00:00:00Z"
    return moment.astimezone().strftime("%Y-%m-%dT%H:%M:%SZ") if moment.tzinfo is None \
        else moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _package(index: int, purl: str) -> dict[str, Any]:
    """One SPDX package from a purl (versionInfo omitted when the purl has no version)."""

    _purl_type, name, version = parse_purl(purl)
    package: dict[str, Any] = {
        "SPDXID": f"SPDXRef-Package-{index}",
        "name": name or purl,
        "downloadLocation": "NOASSERTION",
        "externalRefs": [
            {
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": purl,
            }
        ],
    }
    if version:
        package["versionInfo"] = version
    return package


def spdx_document(document: dict[str, Any]) -> dict[str, Any]:
    """Transform the report document into an SPDX 2.3 document dict."""

    tool_version = document.get("tool", {}).get("version", "")
    run_id = document.get("run_id", "")
    purls = distinct_purls(document)
    packages = [_package(i, purl) for i, purl in enumerate(purls)]
    relationships = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": package["SPDXID"],
        }
        for package in packages
    ]
    return {
        "spdxVersion": SPDX_VERSION,
        "dataLicense": _DATA_LICENSE,
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"finlexpurple-sbom-{run_id}" if run_id else "finlexpurple-sbom",
        "documentNamespace": f"{_DOC_NAMESPACE_BASE}/{uuid.uuid5(_NAMESPACE_UUID, run_id)}",
        "creationInfo": {
            "created": _spdx_timestamp(document.get("generated_at")),
            "creators": [f"Tool: finlexpurple-{tool_version}"],
        },
        "packages": packages,
        "relationships": relationships,
    }


def render_spdx(document: dict[str, Any]) -> str:
    """Render the report document as an SPDX 2.3 document (JSON text)."""

    return json.dumps(spdx_document(document), indent=2, ensure_ascii=True, sort_keys=True) + "\n"
