"""Replay results and status assignment (Phase 11; decisions.md §6, Layer 3).

A finding becomes ``verified`` **only** when a replay module reports that the
exploit was reproduced by code (``reproduced is True``). Anything else — the
replay did not reproduce it, or no replay engine exists for the class — leaves
the finding ``reported``. ``human_confirmed`` is never set here; only a human
action (Phase 8/later) sets that. There is deliberately no path from an LLM's
opinion to ``verified``.
"""

from __future__ import annotations

from dataclasses import dataclass

from finlexpurple.detectors.schema import FindingStatus


@dataclass(frozen=True)
class ReplayResult:
    """The outcome of a replay attempt.

    ``reproduced`` is ``True`` (the exploit re-executed and the signal
    reproduced), ``False`` (re-executed, did not reproduce), or ``None`` (no
    replay engine / collaborator available for this class). ``log`` is a plain,
    deterministic record of what the replay did.
    """

    reproduced: bool | None
    log: str


def status_for(result: ReplayResult) -> FindingStatus:
    """Map a replay result to a finding status.

    Only a reproduced exploit yields ``verified``; everything else stays
    ``reported``. ``human_confirmed`` is never produced here.
    """

    if result.reproduced is True:
        return FindingStatus.VERIFIED
    return FindingStatus.REPORTED
