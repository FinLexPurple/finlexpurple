"""Coupon-abuse replay — re-apply + durable-discount confirmation (Unit 2.2).

Re-applies a captured ``coupon_abuse`` finding's client-supplied coupon and
decides, by deterministic code over the re-executed evidence, whether the bogus
coupon durably discounted the order:

* ``REPRODUCED`` — the coupon is accepted (HTTP 2xx) **and** an independent
  in-scope read-back confirms the illegitimate discount is durably applied to the
  order (the bogus code is recorded on the persisted order). -> VERIFIED
* ``NOT_REPRODUCED`` — the server rejected/recomputed (coupon refused), or it
  accepted it but the read-back shows the discount was **not** persisted. (Not
  "coupons are safe" — only that this replay did not reproduce it.)
* ``INCONCLUSIVE`` — the coupon was accepted but durable discount could not be
  confirmed (no read-back available, or it could not tell).
* ``BLOCKED`` — approval for the state-changing re-execution was not granted.
* ``NO_ENGINE`` — the replay could not run (no prober / gate, or no captured
  ``param=code`` to re-apply). -> REPORTED

Applying a coupon mutates the cart/order, so it always routes through the Phase 8
approval gate first; the gate category is the finding's own agent, so a
Teller/Vault-origin finding is hard-gated and can never auto-run. The LLM is
never consulted; acceptance alone is deliberately never enough for ``REPRODUCED``
— a confirmed durable discount is required, and the confirmer must read REAL
in-scope order state, never synthesize a discount.
"""

from __future__ import annotations

from collections.abc import Callable

from finlexpurple.detectors.prober import Prober, ProbeResponse
from finlexpurple.detectors.schema import Finding
from finlexpurple.gates.approval_gate import ApprovalGate, GateAction, GateOutcome
from finlexpurple.verifier.status import ReplayOutcome, ReplayResult

# Given the captured finding and the applied coupon code, report whether durable
# order state now shows the illegitimate discount (True), confirms it does NOT
# (False), or cannot be confirmed (None). A deployment wires this to a real
# in-scope read of the persisted order (an order-status oracle); it must observe
# real server state, never guess.
CouponConfirmer = Callable[[Finding, str], bool | None]

# Standard-gate default when a finding carries no agent (mirrors price_tampering).
_DEFAULT_CATEGORY = "cashier"

# Gate outcomes under which a state-changing re-execution may proceed.
_PROCEED = (GateOutcome.APPROVED, GateOutcome.ALLOWED)


def _accepted(response: ProbeResponse) -> bool:
    """The server appears to accept the applied coupon: a 2xx status."""

    return 200 <= response.status_code < 300


def replay(
    finding: Finding,
    prober: Prober | None,
    gate: ApprovalGate | None,
    coupon_confirmer: CouponConfirmer | None,
) -> ReplayResult:
    """Re-apply the captured coupon behind the gate; reproduced only if durably discounted."""

    if prober is None or gate is None:
        return ReplayResult(
            None, "coupon-abuse replay requires a prober and an approval gate; not provided.",
            outcome=ReplayOutcome.NO_ENGINE,
        )
    if "=" not in finding.payload:
        return ReplayResult(
            None,
            "coupon-abuse replay needs a captured 'param=code' coupon to re-apply; none present.",
            outcome=ReplayOutcome.NO_ENGINE,
        )
    param, _, code = finding.payload.partition("=")

    category = (finding.agent or _DEFAULT_CATEGORY).strip().lower()
    outcome = gate.resolve(GateAction(
        description=f"re-apply client-supplied coupon {code!r} to {finding.url}",
        category=category,
        state_changing=True,
    ))
    if outcome not in _PROCEED:
        return ReplayResult(
            None,
            f"not replayed: approval not granted for a state-changing re-execution "
            f"(gate outcome: {outcome.value}); replay blocked.",
            outcome=ReplayOutcome.BLOCKED,
        )

    response = prober.request(
        finding.method, finding.url, params={param: code}, headers=finding.headers or None
    )
    if not _accepted(response):
        return ReplayResult(
            False,
            f"re-applied coupon; server rejected it (HTTP {response.status_code}) "
            "— coupon validated / refused — not reproduced.",
            outcome=ReplayOutcome.NOT_REPRODUCED,
        )

    # Accepted. REPRODUCED requires a confirmed durable discount; acceptance of a
    # bogus coupon alone is never sufficient, and no confirmer => inconclusive.
    if coupon_confirmer is None:
        return ReplayResult(
            None,
            "coupon accepted (HTTP 2xx) but no in-scope read-back was available to confirm "
            "the discount persisted on the order — inconclusive.",
            outcome=ReplayOutcome.INCONCLUSIVE,
        )
    discounted = coupon_confirmer(finding, code)
    if discounted is True:
        return ReplayResult(
            True,
            "coupon accepted and the illegitimate discount is durably applied to the order in "
            "in-scope state — exploit reproduced.",
            outcome=ReplayOutcome.REPRODUCED,
        )
    if discounted is False:
        return ReplayResult(
            False,
            "coupon accepted but the in-scope read-back shows the discount was not persisted "
            "— not reproduced.",
            outcome=ReplayOutcome.NOT_REPRODUCED,
        )
    return ReplayResult(
        None,
        "coupon accepted but durable discount could not be confirmed by the read-back "
        "— inconclusive.",
        outcome=ReplayOutcome.INCONCLUSIVE,
    )
