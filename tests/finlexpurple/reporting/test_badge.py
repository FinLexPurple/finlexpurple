"""Phase 16: badges are plain text labels, never emoji."""

from __future__ import annotations

from finlexpurple.detectors.schema import FindingStatus
from finlexpurple.reporting.badge import badge_for


def test_labels_are_the_three_text_states() -> None:
    assert badge_for(FindingStatus.VERIFIED) == "[VERIFIED]"
    assert badge_for(FindingStatus.REPORTED) == "[REPORTED]"
    assert badge_for(FindingStatus.HUMAN_CONFIRMED) == "[HUMAN-CONFIRMED]"


def test_badges_are_pure_ascii_no_emoji() -> None:
    for status in FindingStatus:
        label = badge_for(status)
        assert label.isascii()  # no emoji / decorative glyphs (§6)
        assert label.startswith("[") and label.endswith("]")
