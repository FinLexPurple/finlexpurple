"""Phase 11: quote-grounding rejects claims citing absent evidence."""

from __future__ import annotations

import pytest

from finlexpurple.detectors.schema import Finding
from finlexpurple.verifier.quote_grounding import (
    UngroundedClaimError,
    ground_or_reject,
    is_grounded,
)


def _finding() -> Finding:
    return Finding.new(
        vulnerability_class="sqli",
        method="GET",
        url="https://t.invalid/search",
        payload="q='",
        response_snapshot="You have an error in your SQL syntax near ''",
        expected_signal="SQL error string in response",
    )


def test_grounded_claim_passes() -> None:
    finding = _finding()
    ground_or_reject(["SQL syntax", "q='"], finding)  # both present in evidence
    assert is_grounded(["error in your SQL"], finding)


def test_ungrounded_claim_is_rejected() -> None:
    finding = _finding()
    with pytest.raises(UngroundedClaimError, match="not present"):
        ground_or_reject(["dropped the entire users table"], finding)
    assert is_grounded(["a value never captured"], finding) is False
