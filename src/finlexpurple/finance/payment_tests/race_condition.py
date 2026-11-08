"""Race-condition / double-processing: a passive candidate check plus structural capture
(Phase 19a + Unit 2.5).

The passive :func:`check` is the original read-only surface heuristic — it flags
payment/transfer endpoints (and, since Unit 2.5, check-then-act endpoints) by path as
``reported`` candidates; that double-processing must be tested under the gate, never by
auto-concurrency. This is what ``run_all`` uses, and the scan path is untouched.

Unit 2.5 adds the **structural** active capture: on a check-then-act endpoint (a
single-use redeem / store-credit surface with no idempotency key or lock), it emits a
finding carrying the re-sendable request for a later **bounded, gated** concurrency
replay. Capture here deliberately does **not** send anything — exercising the operation
would consume the single-use resource and defeat the race the replay must run. The
replay is verified only when a bounded concurrent burst plus an in-scope read-back show
the operation durably applied **more than once** this run; a genuine race is
non-deterministic, so the honest outcome is usually ``INCONCLUSIVE`` (a human-review
lead), never auto-VERIFIED.
"""

from __future__ import annotations

from finlexpurple.detectors.prober import Prober
from finlexpurple.detectors.schema import Finding, Severity
from finlexpurple.finance.payment_tests._common import (
    candidate_finding,
    path_of,
    race_finding,
)
from finlexpurple.recon.endpoint_catalog import Endpoint

# The original Phase-19a surface markers: payment/transfer endpoints where
# double-processing must be tested under the gate.
_MARKERS = ("pay", "checkout", "transfer", "withdraw", "purchase", "charge")

# Check-then-act markers (Unit 2.5): single-use redeem / store-credit surfaces whose
# guard (`if not already redeemed`) can be bypassed by concurrent requests.
_RACE_MARKERS = ("redeem", "voucher", "claim", "giftcard", "gift-card", "store-credit")

# The order the redeem endpoint acts on, and whose persisted redemption/credit state
# the read-back confirmer inspects. A fixed sentinel known to the CLI, like
# refund_abuse.REFUND_ORDER_ID — a dedicated single-use voucher order so the race is
# isolated from the cart / status / refund mutations.
RACE_ORDER_ID = "ord-voucher-0001"


def _is_classic_surface(endpoint: Endpoint) -> bool:
    """True for the original payment/transfer candidate surface (passive heuristic)."""

    return any(marker in path_of(endpoint) for marker in _MARKERS)


def looks_like_race(endpoint: Endpoint) -> bool:
    """True for a check-then-act endpoint: a single-use redeem / store-credit surface.

    The path check keeps the structural capture off ordinary payment endpoints (whose
    double-processing concern is already the passive candidate) and onto the single-use
    redeem surface the gated concurrency replay targets.
    """

    return any(marker in path_of(endpoint) for marker in _RACE_MARKERS)


def check(
    endpoints: list[Endpoint], *, agent: str, prober: Prober | None = None
) -> list[Finding]:
    """Flag race-condition surfaces; passively (by path) or by structural check-then-act capture.

    * **Passive** (no prober) — one prose candidate per payment/transfer **or**
      check-then-act endpoint, keyed on the path marker only (the original Phase-19a
      behaviour ``run_all`` relies on, broadened by Unit 2.5 to the redeem surface; the
      scan path is untouched). Double-processing must be tested under the gate — never
      with auto-concurrency.
    * **Active** (a prober) — on a check-then-act endpoint, emit a finding carrying the
      re-sendable request for a later **bounded, gated** concurrency replay. This is a
      **structural** capture: it does NOT send the request (sending would consume the
      single-use resource and defeat the race). The ``prober`` is accepted for a uniform
      signature with the other financial checks but is intentionally not used to send
      here. Findings are always ``reported`` — capture never verifies.
    """

    del prober  # structural capture: the re-sendable request is emitted, never sent here
    findings: list[Finding] = []
    for endpoint in endpoints:
        if not looks_like_race(endpoint):
            # Passive classic surface only (payment/transfer). Preserved Phase-19a behaviour.
            if _is_classic_surface(endpoint):
                findings.append(candidate_finding(
                    endpoint, vclass="race_condition",
                    reason=(
                        "payment/transfer endpoint; double-processing must be tested under the gate "
                        "(no auto-concurrency)"
                    ),
                    severity=Severity.MEDIUM, agent=agent,
                ))
            continue
        # Check-then-act surface: a reported candidate always; the gated concurrency
        # replay (behind the financial specialist) owns verification.
        findings.append(race_finding(
            endpoint, descriptor=path_of(endpoint), severity=Severity.HIGH, agent=agent,
        ))
    return findings
