"""Unit 2.2: coupon-abuse capture end-to-end through the financial specialist
(apply bogus coupon -> gated re-apply -> order read-back -> VERIFIED / NOT_REPRODUCED)."""

from __future__ import annotations

from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.detectors.schema import FindingStatus
from finlexpurple.finance.payment_tests import coupon_abuse, financial_specialist
from finlexpurple.gates.approval_gate import ApprovalGate
from finlexpurple.recon.endpoint_catalog import Endpoint

_ORIGIN = "http://lab.invalid"
_COUPON_EP = Endpoint(method="POST", url=f"{_ORIGIN}/cart/coupon", parameters=("code",))


class _CouponLab:
    """Fake Scope-4 surface: /cart/coupon trusts any code; the order oracle shows
    the applied code when the discount persisted (leak) or not (scoped)."""

    def __init__(self, *, leak: bool) -> None:
        self._leak = leak

    def request(self, method, url, *, params=None, headers=None, body=None) -> ProbeResponse:
        if url.endswith("/cart/coupon"):
            return ProbeResponse(status_code=200, headers={}, text='{"applied": true}')
        if "/orders/" in url:
            total = "0.00" if self._leak else "49.99"
            code = coupon_abuse._SENTINEL_CODE if self._leak else "none"
            return ProbeResponse(status_code=200, headers={},
                                 text=f'{{"id":"ord-1001","coupon":"{code}","amount":"{total}"}}')
        return ProbeResponse(status_code=404, headers={}, text="")


def _gate() -> ApprovalGate:
    return ApprovalGate(True, interactive=True, confirm_fn=lambda _p: True)


def _confirmer(prober: _CouponLab):
    def confirm(finding, code: str) -> bool | None:
        return code in prober.request("GET", f"{_ORIGIN}/orders/ord-1001").text
    return confirm


def test_capture_reaches_verified_on_a_vulnerable_coupon_endpoint() -> None:
    prober = _CouponLab(leak=True)
    findings = financial_specialist.capture_and_verify(
        _COUPON_EP, agent="cashier", prober=prober, gate=_gate(), coupon_confirmer=_confirmer(prober),
    )
    coupon = [f for f in findings if f.vulnerability_class == "coupon_abuse"]
    assert len(coupon) == 1 and coupon[0].status is FindingStatus.VERIFIED


def test_capture_not_reproduced_when_discount_does_not_persist() -> None:
    prober = _CouponLab(leak=False)
    findings = financial_specialist.capture_and_verify(
        _COUPON_EP, agent="cashier", prober=prober, gate=_gate(), coupon_confirmer=_confirmer(prober),
    )
    coupon = [f for f in findings if f.vulnerability_class == "coupon_abuse"]
    assert len(coupon) == 1 and coupon[0].status is FindingStatus.NOT_REPRODUCED


def test_without_a_gate_coupon_stays_reported() -> None:
    prober = _CouponLab(leak=True)
    findings = financial_specialist.capture_and_verify(
        _COUPON_EP, agent="cashier", prober=prober, gate=None, coupon_confirmer=_confirmer(prober),
    )
    coupon = [f for f in findings if f.vulnerability_class == "coupon_abuse"]
    assert len(coupon) == 1 and coupon[0].status is FindingStatus.REPORTED


def test_looks_like_coupon_only_matches_coupon_endpoints() -> None:
    assert coupon_abuse.looks_like_coupon(_COUPON_EP) is True
    assert coupon_abuse.looks_like_coupon(
        Endpoint(method="GET", url=f"{_ORIGIN}/", parameters=("q",))
    ) is False
