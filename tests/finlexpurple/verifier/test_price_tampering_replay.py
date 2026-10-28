"""Task 2: price-tampering replay — gated re-execution + charged/reflected/rejected.

All pass/fail is deterministic code over re-executed evidence. [VERIFIED] requires
a confirmed durable charge; reflection alone is only [REPORTED]; a state-changing
re-execution runs only behind the approval gate, and a Teller-origin finding is
hard-gated so it can never auto-run even with approval disabled.
"""

from __future__ import annotations

from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.detectors.schema import Finding
from finlexpurple.gates.approval_gate import ApprovalGate
from finlexpurple.verifier.replay import price_tampering_replay as ptr


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


def test_charged_is_verified() -> None:
    result = ptr.replay(_finding(), _FakeProber(_reflects), _approved(), lambda f, v: True)
    assert result.reproduced is True
    assert "charged" in result.log


def test_reflection_only_is_not_reproduced() -> None:
    result = ptr.replay(_finding(), _FakeProber(_reflects), _approved(), lambda f, v: False)
    assert result.reproduced is False
    assert "reflection-only" in result.log


def test_reflection_without_confirmer_is_not_reproduced() -> None:
    result = ptr.replay(_finding(), _FakeProber(_reflects), _approved(), None)
    assert result.reproduced is False
    assert "reflection-only" in result.log


def test_unconfirmable_state_is_not_reproduced() -> None:
    result = ptr.replay(_finding(), _FakeProber(_reflects), _approved(), lambda f, v: None)
    assert result.reproduced is False
    assert "reflection-only" in result.log


def test_rejected_price_is_not_reproduced() -> None:
    result = ptr.replay(_finding(), _FakeProber(_rejects), _approved(), lambda f, v: True)
    assert result.reproduced is False
    assert "rejected" in result.log


def test_denied_approval_does_not_execute() -> None:
    prober = _FakeProber(_reflects)
    result = ptr.replay(_finding(), prober, _denied(), lambda f, v: True)
    assert result.reproduced is None
    assert "approval not granted" in result.log
    assert prober.calls == []  # never re-executed


def test_paused_non_interactive_does_not_execute() -> None:
    prober = _FakeProber(_reflects)
    result = ptr.replay(_finding(), prober, _paused(), lambda f, v: True)
    assert result.reproduced is None
    assert prober.calls == []


def test_missing_prober_or_gate_cannot_run() -> None:
    assert ptr.replay(_finding(), None, _approved(), lambda f, v: True).reproduced is None
    assert ptr.replay(_finding(), _FakeProber(_reflects), None, lambda f, v: True).reproduced is None


def test_non_concrete_payload_cannot_run() -> None:
    bad = Finding.new(
        vulnerability_class="price_tampering", method="GET", url="http://t/c",
        payload="price_tampering:prose label", agent="cashier",
    )
    assert ptr.replay(bad, _FakeProber(_reflects), _approved(), lambda f, v: True).reproduced is None


def test_cashier_config_allow_executes_but_teller_is_hard_gated() -> None:
    # Standard-gate 'cashier' with approval disabled -> config-allowed -> executes.
    cashier = ptr.replay(_finding("cashier"), _FakeProber(_reflects), _config_allow(), lambda f, v: True)
    assert cashier.reproduced is True
    # Same disabled config, 'teller' origin -> hard-gated -> paused -> never runs.
    prober = _FakeProber(_reflects)
    teller = ptr.replay(_finding("teller"), prober, _config_allow(), lambda f, v: True)
    assert teller.reproduced is None
    assert prober.calls == []
