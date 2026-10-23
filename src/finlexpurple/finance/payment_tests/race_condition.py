"""Race-condition / double-processing candidate check (Phase 19a; §7, §28 #4).

Read-only: this flags candidate endpoints only. It deliberately does NOT fire
concurrent requests — uncontrolled concurrency is never run without the Phase 8
gate and a deterministic, rate-limited harness (deferred, §18 item 5).
"""

from __future__ import annotations

from finlexpurple.detectors.schema import Finding, Severity
from finlexpurple.finance.payment_tests._common import candidate_finding, path_of
from finlexpurple.recon.endpoint_catalog import Endpoint

_MARKERS = ("pay", "checkout", "transfer", "withdraw", "purchase", "charge")


def check(endpoints: list[Endpoint], *, agent: str) -> list[Finding]:
    """Flag payment/transfer endpoints where double-processing should be tested (gated)."""

    findings: list[Finding] = []
    for endpoint in endpoints:
        if any(marker in path_of(endpoint) for marker in _MARKERS):
            findings.append(candidate_finding(
                endpoint, vclass="race_condition",
                reason="payment/transfer endpoint; double-processing must be tested under the gate (no auto-concurrency)",
                severity=Severity.MEDIUM, agent=agent,
            ))
    return findings
