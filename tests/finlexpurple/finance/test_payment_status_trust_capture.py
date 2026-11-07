"""Unit 2.3: payment-status-trust capture end-to-end through the financial specialist
(set client status -> gated re-set -> order read-back -> VERIFIED / NOT_REPRODUCED)."""

from __future__ import annotations

from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.detectors.schema import FindingStatus
from finlexpurple.finance.payment_tests import financial_specialist, payment_status_trust
from finlexpurple.gates.approval_gate import ApprovalGate
from finlexpurple.recon.endpoint_catalog import Endpoint

_ORIGIN = "http://lab.invalid"
_STATUS_EP = Endpoint(method="POST", url=f"{_ORIGIN}/orders/ord-status-0001/status", parameters=("status",))
_WEBHOOK_EP = Endpoint(method="POST", url=f"{_ORIGIN}/payment/webhook", parameters=("event", "order_id", "status"))


class _StatusLab:
    """Fake Scope-5 surface: the status endpoint trusts the client status; the
    order oracle shows the order 'paid' (leak) or 'pending' (scoped)."""

    def __init__(self, *, leak: bool) -> None:
        self._leak = leak

    def request(self, method, url, *, params=None, headers=None, body=None) -> ProbeResponse:
        if url.endswith("/status"):
            return ProbeResponse(status_code=200, headers={}, text='{"ok": true}')
        if "/orders/" in url:
            status = "paid" if self._leak else "pending"
            return ProbeResponse(status_code=200, headers={},
                                 text=f'{{"id":"ord-status-0001","status":"{status}"}}')
        return ProbeResponse(status_code=404, headers={}, text="")


def _gate() -> ApprovalGate:
    return ApprovalGate(True, interactive=True, confirm_fn=lambda _p: True)


def _confirmer(prober: _StatusLab):
    def confirm(finding, status: str) -> bool | None:
        text = prober.request("GET", f"{_ORIGIN}/orders/ord-status-0001").text
        return status in text and "ord-status-0001" in text
    return confirm


def test_capture_reaches_verified_on_a_trusting_status_endpoint() -> None:
    prober = _StatusLab(leak=True)
    findings = financial_specialist.capture_and_verify(
        _STATUS_EP, agent="cashier", prober=prober, gate=_gate(),
        payment_status_confirmer=_confirmer(prober),
    )
    status = [f for f in findings if f.vulnerability_class == "payment_status_trust"]
    assert len(status) == 1 and status[0].status is FindingStatus.VERIFIED


def test_capture_not_reproduced_when_status_does_not_persist() -> None:
    prober = _StatusLab(leak=False)
    findings = financial_specialist.capture_and_verify(
        _STATUS_EP, agent="cashier", prober=prober, gate=_gate(),
        payment_status_confirmer=_confirmer(prober),
    )
    status = [f for f in findings if f.vulnerability_class == "payment_status_trust"]
    assert len(status) == 1 and status[0].status is FindingStatus.NOT_REPRODUCED


def test_looks_like_status_targets_status_paths_not_the_webhook() -> None:
    # The webhook carries a 'status' param but its path is not a status mutation.
    assert payment_status_trust.looks_like_status(_STATUS_EP) is True
    assert payment_status_trust.looks_like_status(_WEBHOOK_EP) is False


def test_without_a_gate_payment_status_stays_reported() -> None:
    prober = _StatusLab(leak=True)
    findings = financial_specialist.capture_and_verify(
        _STATUS_EP, agent="cashier", prober=prober, gate=None,
        payment_status_confirmer=_confirmer(prober),
    )
    status = [f for f in findings if f.vulnerability_class == "payment_status_trust"]
    assert len(status) == 1 and status[0].status is FindingStatus.REPORTED
