"""Client-trusted payment-status candidate check (Phase 19a; §7)."""

from __future__ import annotations

from finlexpurple.detectors.schema import Finding, Severity
from finlexpurple.finance.payment_tests._common import candidate_finding, param_set
from finlexpurple.recon.endpoint_catalog import Endpoint

_PARAMS = {"status", "paid", "payment_status", "state", "success"}


def check(endpoints: list[Endpoint], *, agent: str) -> list[Finding]:
    """Flag endpoints that may trust a client-supplied payment status."""

    findings: list[Finding] = []
    for endpoint in endpoints:
        hits = _PARAMS & param_set(endpoint)
        if hits:
            findings.append(candidate_finding(
                endpoint, vclass="payment_status_trust",
                reason=f"payment-status parameter(s) {sorted(hits)} may be trusted from the client",
                severity=Severity.HIGH, agent=agent,
            ))
    return findings
