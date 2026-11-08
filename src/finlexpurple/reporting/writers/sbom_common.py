"""Shared helpers for the SBOM writers (CycloneDX + SPDX, Unit 3.2).

Both SBOM writers describe the **dependency surface** carried in the one report
document — specifically the ``purl`` on each finding (frozen in Unit 1.3, and set
**only** when a detector has a real package coordinate, never invented). These helpers
turn those purls into the per-writer component/package records.

If no finding carries a purl (e.g. a pure web scan, where dependency scanning is not
wired into the run), ``distinct_purls`` returns an empty list and the writers emit an
SBOM with no components/packages — the honest "emit what the report contains; do not
fabricate" behaviour the spec requires.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import unquote


def parse_purl(purl: str) -> tuple[str, str, str | None]:
    """Parse a Package URL into ``(type, name, version)``; version is ``None`` when absent.

    Handles the ``pkg:type/namespace*/name@version?qualifiers#subpath`` grammar enough for
    the coordinates our detectors emit (``pkg:pypi/requests@2.0.0``, ``pkg:npm/left-pad``,
    container purls). The name is the last path segment; qualifiers/subpath are dropped.
    """

    body = purl.removeprefix("pkg:")
    body = body.split("#", 1)[0].split("?", 1)[0]
    version: str | None = None
    if "@" in body:
        body, raw_version = body.rsplit("@", 1)
        version = unquote(raw_version) or None
    segments = [seg for seg in body.split("/") if seg]
    purl_type = segments[0].lower() if segments else ""
    name = unquote(segments[-1]) if len(segments) >= 2 else ""
    return purl_type, name, version


def distinct_purls(document: dict[str, Any]) -> list[str]:
    """The sorted, de-duplicated purls carried by the report document's findings."""

    seen = {
        finding["purl"]
        for finding in document.get("findings", [])
        if finding.get("purl")
    }
    return sorted(seen)


def verified_purl_findings(document: dict[str, Any]) -> list[dict[str, Any]]:
    """Findings that carry a purl AND are ``verified`` — the verified-exploitable set (VEX)."""

    return [
        finding
        for finding in document.get("findings", [])
        if finding.get("purl") and finding.get("status") == "verified"
    ]
