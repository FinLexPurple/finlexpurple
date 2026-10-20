"""Cache-poisoning replay — stub (Phase 11; decisions.md §6).

A replay engine for cache poisoning (and any class beyond the four MVP ones) is
out of scope for the initial release. This returns a 'no replay engine' result
so the finding stays honestly `reported`, never a guess.
"""

from __future__ import annotations

from finlexpurple.detectors.schema import Finding
from finlexpurple.verifier.status import ReplayResult


def replay(finding: Finding) -> ReplayResult:
    """Return a no-engine result; cache-poisoning findings stay reported."""

    del finding
    return ReplayResult(None, "no replay engine for cache_poisoning yet (out of scope for the initial release).")
