"""Scan mode, confidence, and honest labeling for supply-chain findings (§25).

Decisions.md §25 requires that supply-chain findings state which mode produced
them and that offline findings carry *lower, clearly-labeled* confidence,
"consistent with the verification ethos — we never overclaim what was not
verified against a live source." The Finding schema has no confidence field, so
this module carries mode + confidence inside the finding's human-facing
``expected_signal`` and a structured ``response_snapshot``, which the reporting
phase (16) reads. That keeps the labeling explicit without a schema change.
"""

from __future__ import annotations

import json
from enum import Enum
from typing import Any


class ScanMode(str, Enum):
    """Whether a check was verified against a live source or shipped data."""

    ONLINE = "online"
    OFFLINE = "offline"


class Confidence(str, Enum):
    """How strongly a finding is asserted; offline is deliberately lower (§25)."""

    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


def offline_confidence(online_confidence: Confidence) -> Confidence:
    """Downgrade a confidence for offline mode (never overclaim, §25).

    An online HIGH becomes OFFLINE MEDIUM; anything already MEDIUM/LOW becomes
    LOW. There is no way for an offline check to keep HIGH confidence.
    """

    if online_confidence is Confidence.HIGH:
        return Confidence.MEDIUM
    return Confidence.LOW


def confidence_for(mode: ScanMode, online_confidence: Confidence) -> Confidence:
    """The effective confidence for a finding given the mode it ran in."""

    return online_confidence if mode is ScanMode.ONLINE else offline_confidence(online_confidence)


def labeled_signal(message: str, *, mode: ScanMode, confidence: Confidence) -> str:
    """A human-facing signal string with the mode and confidence spelled out."""

    return f"{message} [mode={mode.value}; confidence={confidence.value}]"


def labeled_snapshot(data: dict[str, Any], *, mode: ScanMode, confidence: Confidence) -> str:
    """A structured evidence snapshot carrying the mode/confidence labels.

    The reporting phase reads ``scan_mode``/``confidence`` back from here; the
    rest of ``data`` is the verbatim evidence for the specific check.
    """

    enriched = {**data, "scan_mode": mode.value, "confidence": confidence.value}
    return json.dumps(enriched, sort_keys=True)
