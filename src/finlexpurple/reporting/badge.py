"""Verification-status badges as plain text labels (Phase 16; decisions.md §6).

The three-state badge is the product's core credibility signal. It is rendered
as a **text label** — ``[VERIFIED]`` / ``[REPORTED]`` / ``[HUMAN-CONFIRMED]`` —
in the CLI and Markdown report. **No emoji or decorative glyphs anywhere** (§6
retires the earlier ✅/⚠️/🔍 badges); the webapp uses a Lucide icon set
instead, which is out of scope for this module.
"""

from __future__ import annotations

from finlexpurple.detectors.schema import FindingStatus

_LABELS = {
    FindingStatus.VERIFIED: "[VERIFIED]",
    FindingStatus.REPORTED: "[REPORTED]",
    FindingStatus.HUMAN_CONFIRMED: "[HUMAN-CONFIRMED]",
}


def badge_for(status: FindingStatus) -> str:
    """Return the plain-text badge label for a finding status."""

    return _LABELS[status]
