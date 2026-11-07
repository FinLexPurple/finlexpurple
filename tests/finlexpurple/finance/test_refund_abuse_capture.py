"""Unit 2.4: refund-abuse capture end-to-end through the financial specialist
(request over-refund -> gated re-send -> refund-status read-back -> VERIFIED / NOT_REPRODUCED)."""

from __future__ import annotations

from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.detectors.schema import FindingStatus
from finlexpurple.finance.payment_tests import financial_specialist, refund_abuse
from finlexpurple.gates.approval_gate import ApprovalGate
from finlexpurple.recon.endpoint_catalog import Endpoint

_ORIGIN = "http://lab.invalid"
_REFUND_EP = Endpoint(method="POST", url=f"{_ORIGIN}/orders/ord-refund-0001/refund", parameters=("amount",))
_CHECKOUT_EP = Endpoint(method="POST", url=f"{_ORIGIN}/checkout", parameters=("amount",))


class _RefundLab:
    """Fake Scope-6 surface: the refund endpoint accepts any amount with no
    amount/idempotency check; the order oracle reports the durable refunded total
    (over-refund, refunded > paid) or a safe one (refunded <= paid)."""

    def __init__(self, *, over_refund: bool) -> None:
        self._over = over_refund

    def request(self, method, url, *, params=None, headers=None, body=None) -> ProbeResponse:
        if url.endswith("/refund"):
            return ProbeResponse(status_code=200, headers={}, text='{"ok": true}')
        if "/orders/" in url:
            refunded = "999.99" if self._over else "0.00"
            text = (
                '<span data-refund-amount="49.99"></span>'
                f'<span data-refund-refunded="{refunded}"></span>'
                "ord-refund-0001"
            )
            return ProbeResponse(status_code=200, headers={}, text=text)
        return ProbeResponse(status_code=404, headers={}, text="")


def _gate() -> ApprovalGate:
    return ApprovalGate(True, interactive=True, confirm_fn=lambda _p: True)


def _confirmer(prober: _RefundLab):
    import re
    paid_re = re.compile(r'data-refund-amount="([0-9.]+)"')
    refunded_re = re.compile(r'data-refund-refunded="([0-9.]+)"')

    def confirm(finding, amount: str) -> bool | None:
        text = prober.request("GET", f"{_ORIGIN}/orders/ord-refund-0001").text
        if "ord-refund-0001" not in text:
            return None
        paid, refunded = paid_re.search(text), refunded_re.search(text)
        if paid is None or refunded is None:
            return None
        return float(refunded.group(1)) > float(paid.group(1))
    return confirm


def test_capture_reaches_verified_on_a_durable_over_refund() -> None:
    prober = _RefundLab(over_refund=True)
    findings = financial_specialist.capture_and_verify(
        _REFUND_EP, agent="cashier", prober=prober, gate=_gate(),
        refund_confirmer=_confirmer(prober),
    )
    refund = [f for f in findings if f.vulnerability_class == "refund_abuse"]
    assert len(refund) == 1 and refund[0].status is FindingStatus.VERIFIED


def test_capture_not_reproduced_when_refund_within_paid() -> None:
    prober = _RefundLab(over_refund=False)
    findings = financial_specialist.capture_and_verify(
        _REFUND_EP, agent="cashier", prober=prober, gate=_gate(),
        refund_confirmer=_confirmer(prober),
    )
    refund = [f for f in findings if f.vulnerability_class == "refund_abuse"]
    assert len(refund) == 1 and refund[0].status is FindingStatus.NOT_REPRODUCED


def test_looks_like_refund_targets_refund_paths_not_the_checkout() -> None:
    # Checkout carries an 'amount' param but its path is a price, not a refund.
    assert refund_abuse.looks_like_refund(_REFUND_EP) is True
    assert refund_abuse.looks_like_refund(_CHECKOUT_EP) is False


def test_without_a_gate_refund_stays_reported() -> None:
    prober = _RefundLab(over_refund=True)
    findings = financial_specialist.capture_and_verify(
        _REFUND_EP, agent="cashier", prober=prober, gate=None,
        refund_confirmer=_confirmer(prober),
    )
    refund = [f for f in findings if f.vulnerability_class == "refund_abuse"]
    assert len(refund) == 1 and refund[0].status is FindingStatus.REPORTED
