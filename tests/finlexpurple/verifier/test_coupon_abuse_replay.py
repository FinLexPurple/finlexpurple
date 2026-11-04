"""Unit 2.2: coupon-abuse replay outcomes (gated re-apply + discount read-back)."""

from __future__ import annotations

from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.detectors.schema import Finding, FindingStatus
from finlexpurple.gates.approval_gate import ApprovalGate
from finlexpurple.verifier import engine
from finlexpurple.verifier.replay import coupon_abuse_replay
from finlexpurple.verifier.status import ReplayOutcome

_COUPON_URL = "https://shop.example/cart/coupon"
_CODE = "FLP-BOGUS-COUPON"


def _finding() -> Finding:
    return Finding.new(
        vulnerability_class="coupon_abuse", method="POST", url=_COUPON_URL,
        payload=f"code={_CODE}", agent="cashier",
    )


def _gate(*, approve: bool) -> ApprovalGate:
    # interactive gate whose human answer is fixed; approve=True -> APPROVED.
    return ApprovalGate(True, interactive=True, confirm_fn=lambda _p: approve)


class _ApplyProber:
    """Accepts the re-applied coupon (2xx); the confirmer is supplied separately."""

    def request(self, method, url, *, params=None, headers=None, body=None) -> ProbeResponse:
        return ProbeResponse(status_code=200, headers={}, text='{"applied": true}')


class _RejectProber:
    def request(self, method, url, *, params=None, headers=None, body=None) -> ProbeResponse:
        return ProbeResponse(status_code=400, headers={}, text="invalid coupon")


def test_reproduced_when_accepted_and_discount_persists() -> None:
    result = coupon_abuse_replay.replay(
        _finding(), _ApplyProber(), _gate(approve=True), lambda f, code: True,
    )
    assert result.outcome is ReplayOutcome.REPRODUCED and result.reproduced is True


def test_not_reproduced_when_server_rejects_the_coupon() -> None:
    result = coupon_abuse_replay.replay(
        _finding(), _RejectProber(), _gate(approve=True), lambda f, code: True,
    )
    assert result.outcome is ReplayOutcome.NOT_REPRODUCED


def test_not_reproduced_when_discount_did_not_persist() -> None:
    result = coupon_abuse_replay.replay(
        _finding(), _ApplyProber(), _gate(approve=True), lambda f, code: False,
    )
    assert result.outcome is ReplayOutcome.NOT_REPRODUCED


def test_inconclusive_when_accepted_but_no_readback() -> None:
    result = coupon_abuse_replay.replay(
        _finding(), _ApplyProber(), _gate(approve=True), None,
    )
    assert result.outcome is ReplayOutcome.INCONCLUSIVE and result.reproduced is None


def test_inconclusive_when_readback_cannot_tell() -> None:
    result = coupon_abuse_replay.replay(
        _finding(), _ApplyProber(), _gate(approve=True), lambda f, code: None,
    )
    assert result.outcome is ReplayOutcome.INCONCLUSIVE


def test_blocked_when_gate_denies() -> None:
    result = coupon_abuse_replay.replay(
        _finding(), _ApplyProber(), _gate(approve=False), lambda f, code: True,
    )
    assert result.outcome is ReplayOutcome.BLOCKED and result.reproduced is None


def test_no_engine_without_prober_or_gate() -> None:
    assert coupon_abuse_replay.replay(_finding(), None, _gate(approve=True), None).outcome \
        is ReplayOutcome.NO_ENGINE
    assert coupon_abuse_replay.replay(_finding(), _ApplyProber(), None, None).outcome \
        is ReplayOutcome.NO_ENGINE


def test_engine_routes_coupon_abuse_to_verified_only_with_a_confirmed_discount() -> None:
    verified = engine.verify(
        _finding(), prober=_ApplyProber(), gate=_gate(approve=True), coupon_confirmer=lambda f, c: True,
    )
    assert verified.status is FindingStatus.VERIFIED
    # Without a gate the state-changing replay cannot run -> stays reported.
    assert engine.verify(_finding(), prober=_ApplyProber()).status is FindingStatus.REPORTED
