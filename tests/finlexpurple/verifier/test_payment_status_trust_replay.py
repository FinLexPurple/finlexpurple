"""Unit 2.3: payment-status-trust replay outcomes (gated re-set + status read-back)."""

from __future__ import annotations

from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.detectors.schema import Finding, FindingStatus
from finlexpurple.gates.approval_gate import ApprovalGate
from finlexpurple.verifier import engine
from finlexpurple.verifier.replay import payment_status_trust_replay
from finlexpurple.verifier.status import ReplayOutcome

_STATUS_URL = "https://shop.example/orders/ord-status-0001/status"


def _finding() -> Finding:
    return Finding.new(
        vulnerability_class="payment_status_trust", method="POST", url=_STATUS_URL,
        payload="status=paid", agent="cashier",
    )


def _gate(*, approve: bool) -> ApprovalGate:
    return ApprovalGate(True, interactive=True, confirm_fn=lambda _p: approve)


class _AcceptProber:
    def request(self, method, url, *, params=None, headers=None, body=None) -> ProbeResponse:
        return ProbeResponse(status_code=200, headers={}, text='{"ok": true}')


class _RejectProber:
    def request(self, method, url, *, params=None, headers=None, body=None) -> ProbeResponse:
        return ProbeResponse(status_code=403, headers={}, text="forbidden")


def test_reproduced_when_accepted_and_status_persists() -> None:
    result = payment_status_trust_replay.replay(
        _finding(), _AcceptProber(), _gate(approve=True), lambda f, s: True,
    )
    assert result.outcome is ReplayOutcome.REPRODUCED and result.reproduced is True


def test_not_reproduced_when_server_rejects() -> None:
    result = payment_status_trust_replay.replay(
        _finding(), _RejectProber(), _gate(approve=True), lambda f, s: True,
    )
    assert result.outcome is ReplayOutcome.NOT_REPRODUCED


def test_not_reproduced_when_status_did_not_persist() -> None:
    result = payment_status_trust_replay.replay(
        _finding(), _AcceptProber(), _gate(approve=True), lambda f, s: False,
    )
    assert result.outcome is ReplayOutcome.NOT_REPRODUCED


def test_inconclusive_without_a_readback() -> None:
    result = payment_status_trust_replay.replay(
        _finding(), _AcceptProber(), _gate(approve=True), None,
    )
    assert result.outcome is ReplayOutcome.INCONCLUSIVE and result.reproduced is None


def test_blocked_when_gate_denies() -> None:
    result = payment_status_trust_replay.replay(
        _finding(), _AcceptProber(), _gate(approve=False), lambda f, s: True,
    )
    assert result.outcome is ReplayOutcome.BLOCKED and result.reproduced is None


def test_no_engine_without_prober_or_gate() -> None:
    assert payment_status_trust_replay.replay(_finding(), None, _gate(approve=True), None).outcome \
        is ReplayOutcome.NO_ENGINE
    assert payment_status_trust_replay.replay(_finding(), _AcceptProber(), None, None).outcome \
        is ReplayOutcome.NO_ENGINE


def test_engine_routes_payment_status_to_verified_only_with_a_confirmed_status() -> None:
    verified = engine.verify(
        _finding(), prober=_AcceptProber(), gate=_gate(approve=True),
        payment_status_confirmer=lambda f, s: True,
    )
    assert verified.status is FindingStatus.VERIFIED
    # Without a gate the state-changing replay cannot run -> stays reported.
    assert engine.verify(_finding(), prober=_AcceptProber()).status is FindingStatus.REPORTED
