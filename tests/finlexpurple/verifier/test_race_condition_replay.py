"""Unit 2.5: race-condition replay outcomes (bounded gated concurrency harness).

The honest-INCONCLUSIVE discipline is the whole point of this unit: the VERIFIED
path is exercised here ONLY through a test double whose in-scope read-back
*deterministically* reports double-processing. A live race is non-deterministic and
usually lands INCONCLUSIVE — these tests never rig a live race to force VERIFIED.
"""

from __future__ import annotations

from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.detectors.schema import Finding, FindingStatus
from finlexpurple.gates.approval_gate import ApprovalGate
from finlexpurple.verifier import engine
from finlexpurple.verifier.replay import race_condition_replay
from finlexpurple.verifier.status import ReplayOutcome

_REDEEM_URL = "https://shop.example/orders/ord-voucher-0001/redeem"


def _finding() -> Finding:
    return Finding.new(
        vulnerability_class="race_condition", method="POST", url=_REDEEM_URL,
        payload="race_condition:/orders/ord-voucher-0001/redeem", agent="cashier",
    )


def _gate(*, approve: bool) -> ApprovalGate:
    return ApprovalGate(True, interactive=True, confirm_fn=lambda _p: approve)


class _AcceptProber:
    """Every concurrent attempt is accepted (2xx)."""

    def request(self, method, url, *, params=None, headers=None, body=None) -> ProbeResponse:
        return ProbeResponse(status_code=200, headers={}, text='{"redeemed": true}')


def test_reproduced_only_when_readback_deterministically_double_processed() -> None:
    # A test double that DETERMINISTICALLY reports double-processing — the only way to
    # VERIFIED. A real race never gets rigged like this; this proves the mapping only.
    result = race_condition_replay.replay(
        _finding(), _AcceptProber(), _gate(approve=True), lambda f, accepted: True,
    )
    assert result.outcome is ReplayOutcome.REPRODUCED and result.reproduced is True


def test_single_application_this_run_is_inconclusive_not_a_clean_negative() -> None:
    # The read-back shows the operation applied once this run: a genuine race's usual,
    # honest outcome — INCONCLUSIVE (a human-review lead), never NOT_REPRODUCED.
    result = race_condition_replay.replay(
        _finding(), _AcceptProber(), _gate(approve=True), lambda f, accepted: False,
    )
    assert result.outcome is ReplayOutcome.INCONCLUSIVE and result.reproduced is None


def test_unconfirmable_readback_is_inconclusive() -> None:
    result = race_condition_replay.replay(
        _finding(), _AcceptProber(), _gate(approve=True), lambda f, accepted: None,
    )
    assert result.outcome is ReplayOutcome.INCONCLUSIVE and result.reproduced is None


def test_inconclusive_without_a_readback() -> None:
    result = race_condition_replay.replay(
        _finding(), _AcceptProber(), _gate(approve=True), None,
    )
    assert result.outcome is ReplayOutcome.INCONCLUSIVE and result.reproduced is None


def test_blocked_when_gate_denies() -> None:
    result = race_condition_replay.replay(
        _finding(), _AcceptProber(), _gate(approve=False), lambda f, accepted: True,
    )
    assert result.outcome is ReplayOutcome.BLOCKED and result.reproduced is None


def test_no_engine_without_prober_or_gate() -> None:
    assert race_condition_replay.replay(_finding(), None, _gate(approve=True), None).outcome \
        is ReplayOutcome.NO_ENGINE
    assert race_condition_replay.replay(_finding(), _AcceptProber(), None, None).outcome \
        is ReplayOutcome.NO_ENGINE


def test_burst_is_bounded_and_single_shot() -> None:
    # The harness fires exactly _BURST requests, once — never a loop, never unbounded.
    sent: list[str] = []

    class _CountingProber:
        def request(self, method, url, *, params=None, headers=None, body=None) -> ProbeResponse:
            sent.append(url)
            return ProbeResponse(status_code=200, headers={}, text="{}")

    race_condition_replay.replay(
        _finding(), _CountingProber(), _gate(approve=True), lambda f, accepted: False,
    )
    assert len(sent) == race_condition_replay._BURST


def test_engine_routes_race_to_verified_only_with_a_deterministic_double_processing() -> None:
    verified = engine.verify(
        _finding(), prober=_AcceptProber(), gate=_gate(approve=True),
        race_confirmer=lambda f, accepted: True,
    )
    assert verified.status is FindingStatus.VERIFIED
    # Without a gate the state-changing concurrent replay cannot run -> stays reported.
    assert engine.verify(_finding(), prober=_AcceptProber()).status is FindingStatus.REPORTED
    # A real single-application read-back stays INCONCLUSIVE, never VERIFIED.
    honest = engine.verify(
        _finding(), prober=_AcceptProber(), gate=_gate(approve=True),
        race_confirmer=lambda f, accepted: False,
    )
    assert honest.status is FindingStatus.INCONCLUSIVE
