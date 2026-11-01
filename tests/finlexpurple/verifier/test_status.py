"""Phase 11: status assignment — verified only on a reproduced replay."""

from __future__ import annotations

from finlexpurple.detectors.schema import FindingStatus
from finlexpurple.verifier.status import ReplayOutcome, ReplayResult, status_for


def test_verified_only_when_reproduced_true() -> None:
    # Legacy (outcome-less) mapping, used unchanged by the web replays.
    assert status_for(ReplayResult(True, "reproduced")) is FindingStatus.VERIFIED
    assert status_for(ReplayResult(False, "did not reproduce")) is FindingStatus.REPORTED
    assert status_for(ReplayResult(None, "no replay engine")) is FindingStatus.REPORTED


def test_structured_outcome_maps_to_precise_status() -> None:
    assert status_for(ReplayResult(True, "", ReplayOutcome.REPRODUCED)) is FindingStatus.VERIFIED
    assert status_for(ReplayResult(False, "", ReplayOutcome.NOT_REPRODUCED)) is FindingStatus.NOT_REPRODUCED
    assert status_for(ReplayResult(None, "", ReplayOutcome.INCONCLUSIVE)) is FindingStatus.INCONCLUSIVE
    assert status_for(ReplayResult(None, "", ReplayOutcome.BLOCKED)) is FindingStatus.BLOCKED
    assert status_for(ReplayResult(None, "", ReplayOutcome.NO_ENGINE)) is FindingStatus.REPORTED


def test_verified_is_reachable_only_via_a_reproduced_replay() -> None:
    # The invariant: no non-REPRODUCED outcome yields VERIFIED, even if a stray
    # reproduced=True is set alongside it (the structured outcome always wins).
    for outcome in (
        ReplayOutcome.NOT_REPRODUCED, ReplayOutcome.INCONCLUSIVE,
        ReplayOutcome.BLOCKED, ReplayOutcome.NO_ENGINE,
    ):
        assert status_for(ReplayResult(True, "", outcome)) is not FindingStatus.VERIFIED
    # The only two VERIFIED routes: a REPRODUCED outcome, or legacy reproduced=True.
    assert status_for(ReplayResult(True, "", ReplayOutcome.REPRODUCED)) is FindingStatus.VERIFIED
    assert status_for(ReplayResult(True, "legacy web replay")) is FindingStatus.VERIFIED
