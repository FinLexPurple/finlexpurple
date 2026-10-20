"""SQLi replay (Phase 11; decisions.md §6, Layer 2).

Re-executes the finding's captured payload against the target and confirms the
SQL-error signal reproduces. Pass/fail is deterministic code over the live
response — the LLM is never consulted. Uses the same signal set as the detector
so detection and verification agree.
"""

from __future__ import annotations

from finlexpurple.detectors import sqli
from finlexpurple.detectors.prober import Prober
from finlexpurple.detectors.schema import Finding
from finlexpurple.verifier.status import ReplayResult


def replay(finding: Finding, prober: Prober | None) -> ReplayResult:
    """Re-run the SQLi payload; verified iff a SQL error reproduces."""

    if prober is None:
        return ReplayResult(None, "SQLi replay requires a prober; none provided.")
    param, sep, value = finding.payload.partition("=")
    params = {param: value} if sep else {param: ""}
    response = prober.request(finding.method, finding.url, params=params)
    if any(sign in response.text.lower() for sign in sqli._SQL_ERROR_SIGNS):
        return ReplayResult(True, f"re-executed {finding.payload!r}; SQL error signature reproduced.")
    return ReplayResult(False, f"re-executed {finding.payload!r}; no SQL error reproduced.")
