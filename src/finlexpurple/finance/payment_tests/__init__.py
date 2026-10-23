"""The payment/banking test suite used by Cashier and Teller (Phase 19a; §7).

Seven read-only surface checks (price tampering, webhook bypass, order/invoice
IDOR, coupon abuse, client-trusted payment status, race-condition
double-processing, refund abuse). Each flags candidate weaknesses as ``reported``
findings; none exploits the target. ``run_all`` runs them all for one agent.
"""

from __future__ import annotations

from finlexpurple.detectors.schema import Finding
from finlexpurple.finance.payment_tests import (
    coupon_abuse,
    order_idor,
    payment_status_trust,
    price_tampering,
    race_condition,
    refund_abuse,
    webhook_bypass,
)
from finlexpurple.recon.endpoint_catalog import Endpoint

_CHECKS = (
    price_tampering.check,
    webhook_bypass.check,
    order_idor.check,
    coupon_abuse.check,
    payment_status_trust.check,
    race_condition.check,
    refund_abuse.check,
)


def run_all(endpoints: list[Endpoint], *, agent: str) -> list[Finding]:
    """Run every payment check over ``endpoints`` and return the combined findings."""

    findings: list[Finding] = []
    for check in _CHECKS:
        findings.extend(check(endpoints, agent=agent))
    return findings
