"""Refund / reversal abuse candidate check (Phase 19a; §7)."""

from __future__ import annotations

from finlexpurple.detectors.schema import Finding, Severity
from finlexpurple.finance.payment_tests._common import candidate_finding, path_of
from finlexpurple.recon.endpoint_catalog import Endpoint

_MARKERS = ("refund", "cancel", "reverse", "chargeback")


def check(endpoints: list[Endpoint], *, agent: str) -> list[Finding]:
    """Flag refund/reversal endpoints (abuse / authorization risk)."""

    findings: list[Finding] = []
    for endpoint in endpoints:
        if any(marker in path_of(endpoint) for marker in _MARKERS):
            findings.append(candidate_finding(
                endpoint, vclass="refund_abuse",
                reason="refund/reversal endpoint; verify authorization and idempotency",
                severity=Severity.MEDIUM, agent=agent,
            ))
    return findings
