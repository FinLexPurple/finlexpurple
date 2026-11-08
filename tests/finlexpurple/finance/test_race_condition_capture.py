"""Unit 2.5: race-condition capture end-to-end through the financial specialist
(structural capture -> gated bounded concurrent burst -> double-processing read-back ->
VERIFIED only on a deterministic double-processing; else honest INCONCLUSIVE).

The lab is never rigged to force VERIFIED: the VERIFIED case here uses a fake oracle
that deterministically reports a double-processed voucher, while the honest case models
a genuine race that applied once this run and stays INCONCLUSIVE.
"""

from __future__ import annotations

from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.detectors.schema import FindingStatus
from finlexpurple.finance.payment_tests import financial_specialist, race_condition
from finlexpurple.gates.approval_gate import ApprovalGate
from finlexpurple.recon.endpoint_catalog import Endpoint

_ORIGIN = "http://lab.invalid"
_REDEEM_EP = Endpoint(method="POST", url=f"{_ORIGIN}/orders/ord-voucher-0001/redeem")
_CHECKOUT_EP = Endpoint(method="POST", url=f"{_ORIGIN}/checkout", parameters=("amount",))


class _VoucherLab:
    """Fake Scope-7 surface: the single-use redeem endpoint accepts the burst; the order
    oracle reports how many times the voucher was durably applied (``data-race-applied``).
    ``applied`` is fixed per instance — this models a deterministic read-back, NOT a rigged
    live race."""

    def __init__(self, *, applied: int) -> None:
        self._applied = applied

    def request(self, method, url, *, params=None, headers=None, body=None) -> ProbeResponse:
        if url.endswith("/redeem"):
            return ProbeResponse(status_code=200, headers={}, text='{"redeemed": true}')
        if "/orders/" in url:
            text = f'<span data-race-applied="{self._applied}"></span>ord-voucher-0001'
            return ProbeResponse(status_code=200, headers={}, text=text)
        return ProbeResponse(status_code=404, headers={}, text="")


def _gate() -> ApprovalGate:
    return ApprovalGate(True, interactive=True, confirm_fn=lambda _p: True)


def _confirmer(prober: _VoucherLab):
    import re
    applied_re = re.compile(r'data-race-applied="([0-9]+)"')

    def confirm(finding, accepted: int) -> bool | None:
        text = prober.request("GET", f"{_ORIGIN}/orders/ord-voucher-0001").text
        if "ord-voucher-0001" not in text:
            return None
        m = applied_re.search(text)
        if m is None:
            return None
        return int(m.group(1)) >= 2
    return confirm


def test_capture_reaches_verified_only_on_deterministic_double_processing() -> None:
    prober = _VoucherLab(applied=2)  # the read-back deterministically shows double-processing
    findings = financial_specialist.capture_and_verify(
        _REDEEM_EP, agent="cashier", prober=prober, gate=_gate(),
        race_confirmer=_confirmer(prober),
    )
    race = [f for f in findings if f.vulnerability_class == "race_condition"]
    assert len(race) == 1 and race[0].status is FindingStatus.VERIFIED


def test_capture_stays_inconclusive_on_a_single_application_this_run() -> None:
    prober = _VoucherLab(applied=1)  # a genuine race that applied once -> honest INCONCLUSIVE
    findings = financial_specialist.capture_and_verify(
        _REDEEM_EP, agent="cashier", prober=prober, gate=_gate(),
        race_confirmer=_confirmer(prober),
    )
    race = [f for f in findings if f.vulnerability_class == "race_condition"]
    assert len(race) == 1 and race[0].status is FindingStatus.INCONCLUSIVE


def test_looks_like_race_targets_redeem_paths_not_the_checkout() -> None:
    assert race_condition.looks_like_race(_REDEEM_EP) is True
    assert race_condition.looks_like_race(_CHECKOUT_EP) is False


def test_without_a_gate_race_stays_reported() -> None:
    prober = _VoucherLab(applied=2)
    findings = financial_specialist.capture_and_verify(
        _REDEEM_EP, agent="cashier", prober=prober, gate=None,
        race_confirmer=_confirmer(prober),
    )
    race = [f for f in findings if f.vulnerability_class == "race_condition"]
    assert len(race) == 1 and race[0].status is FindingStatus.REPORTED
