"""Phase 9: connector interfaces and the out-of-band canary reference impl."""

from __future__ import annotations

from finlexpurple.mcp.connector import Canary, LocalCanary


def test_local_canary_starts_untriggered_and_records_a_callback() -> None:
    canary = LocalCanary(token="abc123")
    assert canary.token == "abc123"
    assert canary.triggered() is False
    canary.trigger()  # simulate the out-of-band callback a real listener observes
    assert canary.triggered() is True
    assert isinstance(canary, Canary)
