"""Phase 19a: the payment test suite produces reported, schema-conformant findings."""

from __future__ import annotations

from finlexpurple.detectors.schema import Finding, FindingStatus
from finlexpurple.finance import payment_tests
from finlexpurple.recon.endpoint_catalog import Endpoint

_ENDPOINTS = [
    Endpoint(method="POST", url="http://t/checkout", parameters=("price", "coupon"), content_type=None),
    Endpoint(method="POST", url="http://t/payment/webhook", parameters=(), content_type=None),
    Endpoint(method="GET", url="http://t/order", parameters=("order_id",), content_type=None),
    Endpoint(method="POST", url="http://t/refund", parameters=(), content_type=None),
    Endpoint(method="POST", url="http://t/confirm", parameters=("status",), content_type=None),
]


def test_run_all_flags_expected_classes_all_reported() -> None:
    findings = payment_tests.run_all(_ENDPOINTS, agent="cashier")
    classes = {f.vulnerability_class for f in findings}
    for expected in ("price_tampering", "coupon_abuse", "webhook_bypass", "order_idor",
                     "refund_abuse", "payment_status_trust", "race_condition"):
        assert expected in classes
    assert all(isinstance(f, Finding) for f in findings)              # schema-conformant
    assert all(f.status is FindingStatus.REPORTED for f in findings)  # never auto-exploited
    assert all(f.agent == "cashier" for f in findings)


def test_clean_endpoints_yield_nothing() -> None:
    clean = [Endpoint(method="GET", url="http://t/about", parameters=(), content_type=None)]
    assert payment_tests.run_all(clean, agent="cashier") == []
