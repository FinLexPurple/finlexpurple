"""Coupon / discount abuse candidate check (Phase 19a; §7)."""

from __future__ import annotations

from finlexpurple.detectors.schema import Finding, Severity
from finlexpurple.finance.payment_tests._common import candidate_finding, param_set
from finlexpurple.recon.endpoint_catalog import Endpoint

_PARAMS = {"coupon", "promo", "discount", "voucher", "promocode"}


def check(endpoints: list[Endpoint], *, agent: str) -> list[Finding]:
    """Flag endpoints taking a coupon/discount parameter (stacking/abuse risk)."""

    findings: list[Finding] = []
    for endpoint in endpoints:
        hits = _PARAMS & param_set(endpoint)
        if hits:
            findings.append(candidate_finding(
                endpoint, vclass="coupon_abuse",
                reason=f"coupon/discount parameter(s) {sorted(hits)}; verify single-use and stacking limits",
                severity=Severity.MEDIUM, agent=agent,
            ))
    return findings
