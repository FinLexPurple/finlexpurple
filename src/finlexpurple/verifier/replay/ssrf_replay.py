"""SSRF replay — out-of-band confirmation (Phase 11; decisions.md §6, Layer 2).

Injects the canary's URL into the finding's URL parameter and confirms SSRF only
if the target actually reaches the canary (an observed out-of-band callback) —
never by the response text. Deterministic; the LLM is never asked.
"""

from __future__ import annotations

from finlexpurple.detectors.prober import Prober
from finlexpurple.detectors.schema import Finding
from finlexpurple.verifier.replay.canary import OutOfBandCanary
from finlexpurple.verifier.status import ReplayResult


def replay(finding: Finding, prober: Prober | None, canary: OutOfBandCanary | None) -> ReplayResult:
    """Verified iff the target fetches the injected canary URL."""

    if prober is None or canary is None:
        return ReplayResult(None, "SSRF replay requires a prober and a canary; not provided.")
    param = finding.payload.split("=", 1)[0]
    prober.request(finding.method, finding.url, params={param: canary.url})
    if canary.triggered():
        return ReplayResult(True, "target fetched the injected canary URL (out-of-band callback observed).")
    return ReplayResult(False, "no out-of-band canary callback observed.")
