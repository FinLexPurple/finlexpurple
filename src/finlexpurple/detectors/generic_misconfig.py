"""Generic security-misconfiguration detector (Phase 10; decisions.md §6).

Deterministic header checks on the endpoint's response: missing baseline
security headers, and a server banner that discloses a version. Detection only
(``reported``). Each finding uses a distinct payload string so their
``finding_id`` values differ on the same endpoint.
"""

from __future__ import annotations

from finlexpurple.detectors.prober import Prober
from finlexpurple.detectors.schema import Finding, Severity
from finlexpurple.recon.endpoint_catalog import Endpoint

AGENT = "hunter"
_SECURITY_HEADERS = ("content-security-policy", "x-content-type-options", "x-frame-options")


def detect(endpoint: Endpoint, prober: Prober) -> list[Finding]:
    """Return findings for missing security headers and a disclosed server version."""

    response = prober.request(endpoint.method, endpoint.url)
    findings: list[Finding] = []

    missing = [header for header in _SECURITY_HEADERS if header not in response.headers]
    if missing:
        findings.append(
            Finding.new(
                vulnerability_class="generic_misconfig",
                method=endpoint.method,
                url=endpoint.url,
                payload="missing-security-headers:" + ",".join(missing),
                expected_signal=f"missing security headers: {', '.join(missing)}",
                severity=Severity.LOW,
                agent=AGENT,
            )
        )

    server = response.headers.get("server", "")
    if server and any(char.isdigit() for char in server):
        findings.append(
            Finding.new(
                vulnerability_class="generic_misconfig",
                method=endpoint.method,
                url=endpoint.url,
                payload="server-banner:" + server,
                response_snapshot=f"Server: {server}",
                expected_signal=f"server version banner disclosed: {server}",
                severity=Severity.INFO,
                agent=AGENT,
            )
        )
    return findings
