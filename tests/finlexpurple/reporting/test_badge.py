"""Phase 16: badges are plain text labels, never emoji."""

from __future__ import annotations

from finlexpurple.detectors.schema import FindingStatus
from finlexpurple.reporting.badge import badge_for, meaning_for


def test_labels_are_the_text_states() -> None:
    assert badge_for(FindingStatus.VERIFIED) == "[VERIFIED]"
    assert badge_for(FindingStatus.REPORTED) == "[REPORTED]"
    assert badge_for(FindingStatus.HUMAN_CONFIRMED) == "[HUMAN-CONFIRMED]"
    assert badge_for(FindingStatus.INCONCLUSIVE) == "[INCONCLUSIVE]"
    assert badge_for(FindingStatus.NOT_REPRODUCED) == "[NOT-REPRODUCED]"
    assert badge_for(FindingStatus.BLOCKED) == "[BLOCKED]"


def test_badges_are_pure_ascii_no_emoji() -> None:
    for status in FindingStatus:
        label = badge_for(status)
        assert label.isascii()  # no emoji / decorative glyphs (§6)
        assert label.startswith("[") and label.endswith("]")


def test_every_status_has_an_ascii_meaning() -> None:
    for status in FindingStatus:
        assert meaning_for(status).isascii()


def test_not_reproduced_wording_never_presents_absence() -> None:
    # NOT_REPRODUCED must never read as "vulnerability absent" / "safe": the
    # wording explicitly disclaims that and marks the finding unconfirmed.
    text = meaning_for(FindingStatus.NOT_REPRODUCED).lower()
    assert "not proof the target is safe" in text
    assert "unconfirmed" in text
