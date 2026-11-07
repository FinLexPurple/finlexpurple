"""Refund-abuse replay — re-send + durable over-refund confirmation (Unit 2.4).

Re-sends a captured ``refund_abuse`` finding's client-supplied refund (e.g.
``amount=999.99``) to the order's refund endpoint and decides, by deterministic
code, whether the server durably over-refunded the order:

* ``REPRODUCED`` — the refund is accepted (HTTP 2xx) **and** an independent
  in-scope refund-status read-back confirms the order's refunded total durably
  **exceeds the amount paid**. Because the endpoint has no idempotency key, the
  gated re-send is itself the duplicate/double-refund corollary. -> VERIFIED
* ``NOT_REPRODUCED`` — the server rejected it (it enforces an amount/idempotency
  check), or it accepted it but the read-back shows the refunded total does **not**
  exceed what was paid. (Not "the app is safe" — only that this replay did not
  reproduce it.)
* ``INCONCLUSIVE`` — accepted but the durable refunded/paid state could not be
  confirmed (no read-back available, or it could not tell).
* ``BLOCKED`` — approval for the state-changing re-execution was not granted.
* ``NO_ENGINE`` — the replay could not run (no prober / gate, or no captured
  ``param=amount`` to re-send). -> REPORTED

Issuing a refund is a state-changing action, so it always routes through the
Phase 8 approval gate first; the gate category is the finding's own agent, so a
Teller/Vault-origin finding is hard-gated and can never auto-run. The re-send is a
single, gated, rate-limited request through the prober — never uncontrolled
concurrency (that is Unit 2.5's concern). The LLM is never consulted; acceptance
alone is never enough for ``REPRODUCED`` — a confirmed durable over-refund is
required, and the confirmer must read REAL in-scope refund state, comparing the
refunded total against the amount paid, never synthesize an over-refund signal.
"""

from __future__ import annotations

from collections.abc import Callable

from finlexpurple.detectors.prober import Prober, ProbeResponse
from finlexpurple.detectors.schema import Finding
from finlexpurple.gates.approval_gate import ApprovalGate, GateAction, GateOutcome
from finlexpurple.verifier.status import ReplayOutcome, ReplayResult

# Given the captured finding and the client-set refund amount, report whether
# durable refund state now shows the order's refunded total exceeding the amount
# paid (True), confirms it does NOT (False), or cannot be confirmed (None). A
# deployment wires this to a real in-scope read of the persisted order (a
# refund-status oracle) and compares refunded against paid itself; it must observe
# real server state, never guess.
RefundConfirmer = Callable[[Finding, str], bool | None]

# Standard-gate default when a finding carries no agent (mirrors price_tampering).
_DEFAULT_CATEGORY = "cashier"

# Gate outcomes under which a state-changing re-execution may proceed.
_PROCEED = (GateOutcome.APPROVED, GateOutcome.ALLOWED)


def _accepted(response: ProbeResponse) -> bool:
    """The server appears to accept the refund: a 2xx status."""

    return 200 <= response.status_code < 300


def replay(
    finding: Finding,
    prober: Prober | None,
    gate: ApprovalGate | None,
    refund_confirmer: RefundConfirmer | None,
) -> ReplayResult:
    """Re-send the captured refund behind the gate; reproduced only if durably over-refunded."""

    if prober is None or gate is None:
        return ReplayResult(
            None, "refund replay requires a prober and an approval gate; not provided.",
            outcome=ReplayOutcome.NO_ENGINE,
        )
    if "=" not in finding.payload:
        return ReplayResult(
            None,
            "refund replay needs a captured 'param=amount' to re-send; none present.",
            outcome=ReplayOutcome.NO_ENGINE,
        )
    param, _, amount = finding.payload.partition("=")

    category = (finding.agent or _DEFAULT_CATEGORY).strip().lower()
    outcome = gate.resolve(GateAction(
        description=f"re-issue client refund {param}={amount!r} on {finding.url}",
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
        finding.method, finding.url, params={param: amount}, headers=finding.headers or None
    )
    if not _accepted(response):
        return ReplayResult(
            False,
            f"re-issued refund; server rejected it (HTTP {response.status_code}) "
            "— an amount/idempotency check held — not reproduced.",
            outcome=ReplayOutcome.NOT_REPRODUCED,
        )

    # Accepted. REPRODUCED requires a confirmed durable over-refund; acceptance
    # alone is never sufficient, and no confirmer => inconclusive.
    if refund_confirmer is None:
        return ReplayResult(
            None,
            "refund accepted (HTTP 2xx) but no in-scope read-back was available to confirm "
            "the refunded total durably exceeds the amount paid — inconclusive.",
            outcome=ReplayOutcome.INCONCLUSIVE,
        )
    over_refunded = refund_confirmer(finding, amount)
    if over_refunded is True:
        return ReplayResult(
            True,
            "refund accepted and the in-scope read-back shows the order's refunded total durably "
            "exceeding the amount paid (no amount/idempotency check) — exploit reproduced.",
            outcome=ReplayOutcome.REPRODUCED,
        )
    if over_refunded is False:
        return ReplayResult(
            False,
            "refund accepted but the in-scope read-back shows the refunded total does not exceed "
            "the amount paid — not reproduced.",
            outcome=ReplayOutcome.NOT_REPRODUCED,
        )
    return ReplayResult(
        None,
        "refund accepted but the durable refunded/paid state could not be confirmed by the "
        "read-back — inconclusive.",
        outcome=ReplayOutcome.INCONCLUSIVE,
    )
