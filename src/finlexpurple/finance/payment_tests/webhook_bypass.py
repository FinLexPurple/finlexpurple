"""Webhook signature-bypass / replay candidate check (Phase 19a; §7)."""

from __future__ import annotations

from finlexpurple.detectors.schema import Finding, Severity
from finlexpurple.finance.payment_tests._common import candidate_finding, path_of
from finlexpurple.recon.endpoint_catalog import Endpoint

_MARKERS = ("webhook", "callback", "/ipn", "notify")


def check(endpoints: list[Endpoint], *, agent: str) -> list[Finding]:
    """Flag payment webhook/callback endpoints (signature-bypass / replay risk)."""

    findings: list[Finding] = []
    for endpoint in endpoints:
        path = path_of(endpoint)
        if any(marker in path for marker in _MARKERS):
            findings.append(candidate_finding(
                endpoint, vclass="webhook_bypass",
                reason="payment webhook/callback endpoint; verify signature validation and replay protection",
                severity=Severity.HIGH, agent=agent,
            ))
    return findings
