"""Price-tampering candidate check (Phase 19a; §7)."""

from __future__ import annotations

from finlexpurple.detectors.schema import Finding, Severity
from finlexpurple.finance.payment_tests._common import candidate_finding, param_set
from finlexpurple.recon.endpoint_catalog import Endpoint

_PRICE_PARAMS = {"price", "amount", "total", "cost", "subtotal", "grandtotal"}


def check(endpoints: list[Endpoint], *, agent: str) -> list[Finding]:
    """Flag endpoints exposing a price-like parameter that may be client-controlled."""

    findings: list[Finding] = []
    for endpoint in endpoints:
        hits = _PRICE_PARAMS & param_set(endpoint)
        if hits:
            findings.append(candidate_finding(
                endpoint, vclass="price_tampering",
                reason=f"price-like parameter(s) {sorted(hits)} may be client-controlled",
                severity=Severity.HIGH, agent=agent,
            ))
    return findings
