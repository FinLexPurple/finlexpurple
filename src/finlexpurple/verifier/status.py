"""Replay results and status assignment (Phase 11; decisions.md §6, Layer 3).

A finding becomes ``verified`` **only** when a replay module reports that the
exploit was reproduced by code. Anything else leaves the finding non-verified.
``human_confirmed`` is never set here; only a human action (Phase 8/later) sets
that. There is deliberately no path from an LLM's opinion to ``verified``.

Phase 18 delegation (Unit 1) makes the non-verified cases precise. A replay may
now carry a structured :class:`ReplayOutcome` that maps to a first-class status
(``not_reproduced`` / ``inconclusive`` / ``blocked``) instead of collapsing to
``reported``. This is **additive**: a replay that sets no ``outcome`` (the
existing web replays) keeps the original reproduced-based mapping unchanged, so
those classes and their tests do not change behaviour. Either way, ``status_for``
remains the ONLY producer of ``verified``, and only on a reproduced replay.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from finlexpurple.detectors.schema import FindingStatus


class ReplayOutcome(str, Enum):
    """The precise outcome of a replay that distinguishes its non-verified cases.

    * ``REPRODUCED`` — the exploit re-executed and its durable impact was
      confirmed by code. The only outcome that yields ``verified``.
    * ``NOT_REPRODUCED`` — it re-executed and did **not** reproduce (server
      rejected/recomputed, or durable state confirms it was not persisted). This
      is not "the vulnerability is absent".
    * ``INCONCLUSIVE`` — it re-executed but durable impact could not be
      confirmed (reflected only, or no state read-back available).
    * ``BLOCKED`` — the state-changing re-execution was not permitted by the
      approval gate, so nothing ran.
    * ``NO_ENGINE`` — the replay could not run at all (missing collaborator,
      non-replayable payload, or no engine for the class); stays ``reported``.
    """

    REPRODUCED = "reproduced"
    NOT_REPRODUCED = "not_reproduced"
    INCONCLUSIVE = "inconclusive"
    BLOCKED = "blocked"
    NO_ENGINE = "no_engine"


@dataclass(frozen=True)
class ReplayResult:
    """The outcome of a replay attempt.

    ``reproduced`` is ``True`` (the exploit re-executed and the signal
    reproduced), ``False`` (re-executed, did not reproduce), or ``None`` (no
    replay engine / collaborator available). ``log`` is a plain, deterministic
    record of what the replay did. ``outcome`` is the optional structured
    outcome (Unit 1): when set it drives the status precisely; when ``None`` the
    legacy reproduced-based mapping applies (unchanged web-replay behaviour).
    """

    reproduced: bool | None
    log: str
    outcome: ReplayOutcome | None = None


# A structured outcome maps to exactly one status. Only REPRODUCED -> VERIFIED.
_OUTCOME_STATUS: dict[ReplayOutcome, FindingStatus] = {
    ReplayOutcome.REPRODUCED: FindingStatus.VERIFIED,
    ReplayOutcome.NOT_REPRODUCED: FindingStatus.NOT_REPRODUCED,
    ReplayOutcome.INCONCLUSIVE: FindingStatus.INCONCLUSIVE,
    ReplayOutcome.BLOCKED: FindingStatus.BLOCKED,
    ReplayOutcome.NO_ENGINE: FindingStatus.REPORTED,
}


def status_for(result: ReplayResult) -> FindingStatus:
    """Map a replay result to a finding status.

    If the replay set a structured ``outcome``, use the precise mapping (only a
    ``REPRODUCED`` outcome yields ``verified``). Otherwise fall back to the
    legacy rule: a ``reproduced is True`` replay yields ``verified`` and anything
    else stays ``reported``. ``human_confirmed`` is never produced here.
    """

    if result.outcome is not None:
        return _OUTCOME_STATUS[result.outcome]
    if result.reproduced is True:
        return FindingStatus.VERIFIED
    return FindingStatus.REPORTED
