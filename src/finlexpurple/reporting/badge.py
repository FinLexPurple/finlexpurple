"""Verification-status badges as plain text labels (Phase 16; decisions.md §6).

The verification-status badge is the product's core credibility signal. It is
rendered as a **text label** — ``[VERIFIED]`` / ``[REPORTED]`` /
``[HUMAN-CONFIRMED]`` and, from Unit 1, ``[INCONCLUSIVE]`` / ``[NOT-REPRODUCED]``
/ ``[BLOCKED]`` — in the CLI and Markdown report. **No emoji or decorative glyphs
anywhere** (§6 retires the earlier badges); the webapp uses a Lucide icon set
instead, which is out of scope for this module.

``meaning_for`` gives the one-line human wording for each status. The wording is
load-bearing for honesty: ``NOT_REPRODUCED`` must **never** be presented as
"vulnerability absent" / "safe" — it means only that this controlled replay did
not reproduce the issue. A test enforces that wording.
"""

from __future__ import annotations

from finlexpurple.detectors.schema import FindingStatus

_LABELS = {
    FindingStatus.VERIFIED: "[VERIFIED]",
    FindingStatus.REPORTED: "[REPORTED]",
    FindingStatus.HUMAN_CONFIRMED: "[HUMAN-CONFIRMED]",
    FindingStatus.INCONCLUSIVE: "[INCONCLUSIVE]",
    FindingStatus.NOT_REPRODUCED: "[NOT-REPRODUCED]",
    FindingStatus.BLOCKED: "[BLOCKED]",
}

# One-line meanings. NOT_REPRODUCED is worded to never imply the target is safe.
_MEANINGS = {
    FindingStatus.VERIFIED: "independently reproduced by a deterministic replay.",
    FindingStatus.REPORTED: "detected but not independently replayed.",
    FindingStatus.HUMAN_CONFIRMED: "confirmed by a human reviewer.",
    FindingStatus.INCONCLUSIVE: (
        "replayed, but durable impact could not be confirmed; neither reproduced nor ruled out."
    ),
    FindingStatus.NOT_REPRODUCED: (
        "this controlled replay did not reproduce the issue; this is not proof the target "
        "is safe or the finding is a false positive - treat it as unconfirmed."
    ),
    FindingStatus.BLOCKED: "the state-changing replay was blocked by the approval gate and did not run.",
}


def badge_for(status: FindingStatus) -> str:
    """Return the plain-text badge label for a finding status."""

    return _LABELS[status]


def meaning_for(status: FindingStatus) -> str:
    """Return the one-line human meaning for a finding status (honest, no false 'safe')."""

    return _MEANINGS[status]
