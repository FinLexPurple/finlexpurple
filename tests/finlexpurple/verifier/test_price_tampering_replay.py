"""Task 2 + Unit 1: price-tampering replay — gated re-execution, precise outcomes.

All pass/fail is deterministic code over re-executed evidence. REPRODUCED (->
VERIFIED) requires a confirmed durable charge; a reflected-but-unconfirmed result
is INCONCLUSIVE (never verified); a rejected/recomputed or confirmed-not-persisted
result is NOT_REPRODUCED; a gate that does not permit the re-execution is BLOCKED;
a replay that cannot run at all is NO_ENGINE. A Teller-origin finding is hard-gated
so it can never auto-run even with approval disabled.
"""

from __future__ import annotations

from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.detectors.schema import Finding
from finlexpurple.gates.approval_gate import ApprovalGate
from finlexpurple.verifier.replay import price_tampering_replay as ptr
from finlexpurple.verifier.status import ReplayOutcome


class _FakeProber:
    def __init__(self, responder) -> None:
        self._responder = responder
        self.calls: list[tuple] = []

    def request(self, method, url, *, params=None, headers=None) -> ProbeResponse:
        self.calls.append((method, url, params or {}, headers or {}))
        return self._responder(params or {}, headers or {})


def _finding(agent: str = "cashier") -> Finding:
    return Finding.new(
        vulnerability_class="price_tampering", method="GET",
        url="http://t/checkout", payload="price=0.01", agent=agent,
    )


def _approved() -> ApprovalGate:
    return ApprovalGate(True, interactive=True, confirm_fn=lambda _p: True)


def _denied() -> ApprovalGate:
    return ApprovalGate(True, interactive=True, confirm_fn=lambda _p: False)


def _paused() -> ApprovalGate:  # approval required, no interactive operator present
    return ApprovalGate(True, interactive=False)


def _config_allow() -> ApprovalGate:  # standard gate with approval disabled
    return ApprovalGate(False, interactive=False)


# A checkout that reflects whatever price it is given, and one that rejects it.
def _reflects(params, headers) -> ProbeResponse:
    return ProbeResponse(200, {}, f"total={params.get('price', '')}")


def _rejects(params, headers) -> ProbeResponse:
    return ProbeResponse(200, {}, "total=49.99")


def test_charged_is_reproduced() -> None:
    result = ptr.replay(_finding(), _FakeProber(_reflects), _approved(), lambda f, v: True)
    assert result.reproduced is True and result.outcome is ReplayOutcome.REPRODUCED
    assert "charged" in result.log


def test_confirmed_not_persisted_is_not_reproduced() -> None:
    result = ptr.replay(_finding(), _FakeProber(_reflects), _approved(), lambda f, v: False)
    assert result.outcome is ReplayOutcome.NOT_REPRODUCED
    assert "not persisted" in result.log


def test_reflection_without_confirmer_is_inconclusive() -> None:
    result = ptr.replay(_finding(), _FakeProber(_reflects), _approved(), None)
    assert result.outcome is ReplayOutcome.INCONCLUSIVE
    assert result.reproduced is not True  # inconclusive is never verified
    assert "inconclusive" in result.log


def test_unconfirmable_state_is_inconclusive() -> None:
    result = ptr.replay(_finding(), _FakeProber(_reflects), _approved(), lambda f, v: None)
    assert result.outcome is ReplayOutcome.INCONCLUSIVE
    assert result.reproduced is not True
    assert "inconclusive" in result.log


def test_rejected_price_is_not_reproduced() -> None:
    result = ptr.replay(_finding(), _FakeProber(_rejects), _approved(), lambda f, v: True)
    assert result.outcome is ReplayOutcome.NOT_REPRODUCED
    assert "rejected" in result.log


def test_denied_approval_is_blocked_and_does_not_execute() -> None:
    prober = _FakeProber(_reflects)
    result = ptr.replay(_finding(), prober, _denied(), lambda f, v: True)
    assert result.outcome is ReplayOutcome.BLOCKED
    assert "approval not granted" in result.log
    assert prober.calls == []  # never re-executed


def test_paused_non_interactive_is_blocked() -> None:
    prober = _FakeProber(_reflects)
    result = ptr.replay(_finding(), prober, _paused(), lambda f, v: True)
    assert result.outcome is ReplayOutcome.BLOCKED
    assert prober.calls == []


def test_missing_prober_or_gate_is_no_engine() -> None:
    a = ptr.replay(_finding(), None, _approved(), lambda f, v: True)
    b = ptr.replay(_finding(), _FakeProber(_reflects), None, lambda f, v: True)
    assert a.outcome is ReplayOutcome.NO_ENGINE and b.outcome is ReplayOutcome.NO_ENGINE


def test_non_concrete_payload_is_no_engine() -> None:
    bad = Finding.new(
        vulnerability_class="price_tampering", method="GET", url="http://t/c",
        payload="price_tampering:prose label", agent="cashier",
    )
    result = ptr.replay(bad, _FakeProber(_reflects), _approved(), lambda f, v: True)
    assert result.outcome is ReplayOutcome.NO_ENGINE


def test_cashier_config_allow_reproduces_but_teller_is_hard_gated() -> None:
    # Standard-gate 'cashier' with approval disabled -> config-allowed -> executes.
    cashier = ptr.replay(_finding("cashier"), _FakeProber(_reflects), _config_allow(), lambda f, v: True)
    assert cashier.outcome is ReplayOutcome.REPRODUCED
    # Same disabled config, 'teller' origin -> hard-gated -> paused -> never runs.
    prober = _FakeProber(_reflects)
    teller = ptr.replay(_finding("teller"), prober, _config_allow(), lambda f, v: True)
    assert teller.outcome is ReplayOutcome.BLOCKED
    assert prober.calls == []
