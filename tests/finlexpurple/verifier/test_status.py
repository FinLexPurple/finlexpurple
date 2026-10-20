"""Phase 11: status assignment — verified only on a reproduced replay."""

from __future__ import annotations

from finlexpurple.detectors.schema import FindingStatus
from finlexpurple.verifier.status import ReplayResult, status_for


def test_verified_only_when_reproduced_true() -> None:
    assert status_for(ReplayResult(True, "reproduced")) is FindingStatus.VERIFIED
    assert status_for(ReplayResult(False, "did not reproduce")) is FindingStatus.REPORTED
    assert status_for(ReplayResult(None, "no replay engine")) is FindingStatus.REPORTED
