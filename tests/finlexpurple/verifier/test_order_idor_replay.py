"""Unit 2.1: order-IDOR replay outcomes (two sessions, owner-view ground truth)."""

from __future__ import annotations

from collections.abc import Callable

from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.detectors.schema import Finding, FindingStatus
from finlexpurple.verifier import engine
from finlexpurple.verifier.replay import order_idor_replay
from finlexpurple.verifier.status import ReplayOutcome

_ORDER_URL = "https://shop.example/orders/ord-alice-0001"
_ALICE = {"Cookie": "session=alice"}
_BOB = {"Cookie": "session=bob"}
_ALICE_BODY = '{"id": "ord-alice-0001", "owner": "alice", "amount": "49.99"}'


def _finding() -> Finding:
    return Finding.new(
        vulnerability_class="order_idor", method="GET", url=_ORDER_URL,
        payload="order_idor:/orders/ord-alice-0001",
    )


class _FakeProber:
    """Serves a response per (url, session cookie) from a fixture map."""

    def __init__(self, by_cookie: Callable[[str | None], ProbeResponse]) -> None:
        self._by_cookie = by_cookie

    def request(self, method, url, *, params=None, headers=None, body=None) -> ProbeResponse:
        cookie = (headers or {}).get("Cookie")
        return self._by_cookie(cookie)


def _prober(bob: ProbeResponse) -> _FakeProber:
    def serve(cookie: str | None) -> ProbeResponse:
        if cookie == "session=alice":
            return ProbeResponse(status_code=200, headers={}, text=_ALICE_BODY)
        return bob
    return _FakeProber(serve)


def test_reproduced_when_bob_gets_alices_exact_object() -> None:
    prober = _prober(ProbeResponse(status_code=200, headers={}, text=_ALICE_BODY))
    result = order_idor_replay.replay(_finding(), prober, (_ALICE, _BOB))
    assert result.outcome is ReplayOutcome.REPRODUCED and result.reproduced is True


def test_not_reproduced_when_bob_is_denied() -> None:
    prober = _prober(ProbeResponse(status_code=403, headers={}, text=""))
    result = order_idor_replay.replay(_finding(), prober, (_ALICE, _BOB))
    assert result.outcome is ReplayOutcome.NOT_REPRODUCED and result.reproduced is False


def test_not_reproduced_when_bob_sees_a_different_object() -> None:
    bob_own = ProbeResponse(status_code=200, headers={},
                            text='{"id": "ord-bob-0001", "owner": "bob", "amount": "9.99"}')
    result = order_idor_replay.replay(_finding(), _prober(bob_own), (_ALICE, _BOB))
    assert result.outcome is ReplayOutcome.NOT_REPRODUCED and result.reproduced is False


def test_inconclusive_when_owner_cannot_read_its_own_object() -> None:
    # Owner itself gets a non-200 (e.g. session expired): no ground truth to compare.
    prober = _FakeProber(lambda cookie: ProbeResponse(status_code=404, headers={}, text=""))
    result = order_idor_replay.replay(_finding(), prober, (_ALICE, _BOB))
    assert result.outcome is ReplayOutcome.INCONCLUSIVE and result.reproduced is None


def test_no_engine_without_prober_or_sessions() -> None:
    assert order_idor_replay.replay(_finding(), None, (_ALICE, _BOB)).outcome is ReplayOutcome.NO_ENGINE
    prober = _prober(ProbeResponse(status_code=200, headers={}, text=_ALICE_BODY))
    assert order_idor_replay.replay(_finding(), prober, None).outcome is ReplayOutcome.NO_ENGINE


def test_engine_routes_order_idor_through_the_registry_to_verified() -> None:
    # End-to-end via the capability registry: the engine maps order_idor to its
    # replay and sets VERIFIED only on a reproduced cross-account read.
    prober = _prober(ProbeResponse(status_code=200, headers={}, text=_ALICE_BODY))
    finding = engine.verify(_finding(), prober=prober, sessions=(_ALICE, _BOB))
    assert finding.status is FindingStatus.VERIFIED

    denied = _prober(ProbeResponse(status_code=403, headers={}, text=""))
    reported = engine.verify(_finding(), prober=denied, sessions=(_ALICE, _BOB))
    assert reported.status is FindingStatus.NOT_REPRODUCED
    # No sessions injected (a plain scan) -> stays reported, never silently verified.
    assert engine.verify(_finding(), prober=prober).status is FindingStatus.REPORTED
