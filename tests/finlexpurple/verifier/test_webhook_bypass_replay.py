"""Unit 2: webhook-bypass replay — gated forged-callback re-execution, precise outcomes.

All pass/fail is deterministic code over the re-executed evidence. REPRODUCED (->
VERIFIED) requires both acceptance of the forged unsigned callback AND an in-scope
read-back confirming the order durably flipped to paid; acceptance without a
confirmed paid-state is INCONCLUSIVE; a rejected callback or a confirmed-not-paid
is NOT_REPRODUCED; a gate that does not permit the re-execution is BLOCKED and
nothing is sent. A Teller-origin finding is hard-gated and can never auto-run.
"""

from __future__ import annotations

from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.detectors.schema import Finding
from finlexpurple.gates.approval_gate import ApprovalGate
from finlexpurple.verifier.replay import webhook_bypass_replay as whr
from finlexpurple.verifier.status import ReplayOutcome


class _FakeProber:
    def __init__(self, status: int) -> None:
        self._status = status
        self.calls: list[tuple] = []

    def request(self, method, url, *, params=None, headers=None, body=None) -> ProbeResponse:
        self.calls.append((method, url, headers or {}, body))
        return ProbeResponse(self._status, {}, "received")


def _finding(agent: str = "cashier") -> Finding:
    return Finding.new(
        vulnerability_class="webhook_bypass", method="POST",
        url="http://t/payment/webhook", payload="webhook_bypass:forged-paid-callback",
        headers={"X-Signature": "invalid"}, body='{"order_id": "flp-probe", "status": "paid"}',
        agent=agent,
    )


def _approved() -> ApprovalGate:
    return ApprovalGate(True, interactive=True, confirm_fn=lambda _p: True)


def _denied() -> ApprovalGate:
    return ApprovalGate(True, interactive=True, confirm_fn=lambda _p: False)


def _config_allow() -> ApprovalGate:
    return ApprovalGate(False, interactive=False)


def test_accepted_and_durably_paid_is_reproduced() -> None:
    result = whr.replay(_finding(), _FakeProber(200), _approved(), lambda f: True)
    assert result.reproduced is True and result.outcome is ReplayOutcome.REPRODUCED
    assert "paid" in result.log


def test_accepted_but_not_paid_is_not_reproduced() -> None:
    result = whr.replay(_finding(), _FakeProber(200), _approved(), lambda f: False)
    assert result.outcome is ReplayOutcome.NOT_REPRODUCED
    assert "not" in result.log


def test_accepted_but_unconfirmed_is_inconclusive() -> None:
    result = whr.replay(_finding(), _FakeProber(200), _approved(), lambda f: None)
    assert result.outcome is ReplayOutcome.INCONCLUSIVE
    assert result.reproduced is not True


def test_accepted_without_confirmer_is_inconclusive() -> None:
    result = whr.replay(_finding(), _FakeProber(200), _approved(), None)
    assert result.outcome is ReplayOutcome.INCONCLUSIVE
    assert result.reproduced is not True


def test_rejected_callback_is_not_reproduced() -> None:
    result = whr.replay(_finding(), _FakeProber(403), _approved(), lambda f: True)
    assert result.outcome is ReplayOutcome.NOT_REPRODUCED
    assert "rejected" in result.log


def test_denied_approval_is_blocked_and_sends_nothing() -> None:
    prober = _FakeProber(200)
    result = whr.replay(_finding(), prober, _denied(), lambda f: True)
    assert result.outcome is ReplayOutcome.BLOCKED
    assert prober.calls == []  # the forged callback was never re-sent


def test_missing_body_is_no_engine() -> None:
    bodyless = Finding.new(
        vulnerability_class="webhook_bypass", method="POST", url="http://t/webhook",
        payload="webhook_bypass:candidate", agent="cashier",
    )
    result = whr.replay(bodyless, _FakeProber(200), _approved(), lambda f: True)
    assert result.outcome is ReplayOutcome.NO_ENGINE


def test_missing_prober_or_gate_is_no_engine() -> None:
    a = whr.replay(_finding(), None, _approved(), lambda f: True)
    b = whr.replay(_finding(), _FakeProber(200), None, lambda f: True)
    assert a.outcome is ReplayOutcome.NO_ENGINE and b.outcome is ReplayOutcome.NO_ENGINE


def test_teller_origin_is_hard_gated_and_never_sends() -> None:
    prober = _FakeProber(200)
    result = whr.replay(_finding("teller"), prober, _config_allow(), lambda f: True)
    assert result.outcome is ReplayOutcome.BLOCKED
    assert prober.calls == []  # hard-gated: config-allow cannot run it
