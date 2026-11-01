"""Webhook-bypass replay — forged-callback re-execution + paid-state confirmation (Unit 2).

Re-executes a captured ``webhook_bypass`` finding's forged, unsigned/invalid-
signature "paid" callback and decides, by deterministic code over the re-executed
evidence, whether the forgery durably flipped the order to paid:

* ``REPRODUCED`` — the forged callback is accepted (HTTP 2xx) **and** an
  independent in-scope read-back confirms the order is durably marked paid. ->
  VERIFIED
* ``NOT_REPRODUCED`` — the server rejected the forged callback (it validated the
  signature / refused the replay), or it accepted it but the read-back shows the
  order was **not** marked paid. (Not "the webhook is secure" — only that this
  replay did not reproduce it.)
* ``INCONCLUSIVE`` — the forged callback was accepted but durable paid-state
  could not be confirmed (no read-back available, or it could not tell).
* ``BLOCKED`` — approval for the state-changing re-execution was not granted.
* ``NO_ENGINE`` — the replay could not run (no prober / gate, or no captured
  forged body). -> REPORTED

Re-sending a forged callback is a state-changing action, so it always routes
through the Phase 8 approval gate first; the gate category is the finding's own
agent, so a Teller/Vault-origin finding is hard-gated and can never auto-run. The
LLM is never consulted; acceptance alone is deliberately never enough for
``REPRODUCED`` — a confirmed durable paid-state is required, and the confirmer
must read REAL in-scope state, never synthesize a "paid" signal.
"""

from __future__ import annotations

from collections.abc import Callable

from finlexpurple.detectors.prober import Prober, ProbeResponse
from finlexpurple.detectors.schema import Finding
from finlexpurple.gates.approval_gate import ApprovalGate, GateAction, GateOutcome
from finlexpurple.verifier.status import ReplayOutcome, ReplayResult

# Given the captured finding, report whether durable state now shows the forged
# order as settled/paid (True), confirms it is NOT (False), or cannot be confirmed
# (None). A deployment wires this to a real in-scope read of persisted order /
# settlement state; it must observe real server state, never guess.
SettlementConfirmer = Callable[[Finding], bool | None]

# Standard-gate default when a finding carries no agent (mirrors price_tampering).
_DEFAULT_CATEGORY = "cashier"

# Gate outcomes under which a state-changing re-execution may proceed.
_PROCEED = (GateOutcome.APPROVED, GateOutcome.ALLOWED)


def _accepted(response: ProbeResponse) -> bool:
    """The server appears to accept the forged callback: a 2xx status."""

    return 200 <= response.status_code < 300


def replay(
    finding: Finding,
    prober: Prober | None,
    gate: ApprovalGate | None,
    settlement_confirmer: SettlementConfirmer | None,
) -> ReplayResult:
    """Re-send the captured forged callback behind the gate; reproduced only if durably paid."""

    if prober is None or gate is None:
        return ReplayResult(
            None, "webhook-bypass replay requires a prober and an approval gate; not provided.",
            outcome=ReplayOutcome.NO_ENGINE,
        )
    if not finding.body:
        return ReplayResult(
            None,
            "webhook-bypass replay needs a captured forged-callback body to re-send; none present.",
            outcome=ReplayOutcome.NO_ENGINE,
        )

    category = (finding.agent or _DEFAULT_CATEGORY).strip().lower()
    outcome = gate.resolve(GateAction(
        description=f"re-send forged webhook callback to {finding.url}",
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
        finding.method, finding.url, headers=finding.headers or None, body=finding.body
    )
    if not _accepted(response):
        return ReplayResult(
            False,
            f"re-sent forged callback; server rejected it (HTTP {response.status_code}) "
            "— signature validated / replay refused — not reproduced.",
            outcome=ReplayOutcome.NOT_REPRODUCED,
        )

    # Accepted. REPRODUCED requires a confirmed durable paid-state; acceptance of
    # an unsigned callback alone is never sufficient, and no confirmer => inconclusive.
    if settlement_confirmer is None:
        return ReplayResult(
            None,
            "forged callback accepted (HTTP 2xx) but no in-scope read-back was available to "
            "confirm the order flipped to paid — inconclusive.",
            outcome=ReplayOutcome.INCONCLUSIVE,
        )
    settled = settlement_confirmer(finding)
    if settled is True:
        return ReplayResult(
            True,
            "forged callback accepted and the order is durably marked paid in in-scope state "
            "— exploit reproduced.",
            outcome=ReplayOutcome.REPRODUCED,
        )
    if settled is False:
        return ReplayResult(
            False,
            "forged callback accepted but the in-scope read-back shows the order was not "
            "marked paid — not reproduced.",
            outcome=ReplayOutcome.NOT_REPRODUCED,
        )
    return ReplayResult(
        None,
        "forged callback accepted but durable paid-state could not be confirmed by the "
        "read-back — inconclusive.",
        outcome=ReplayOutcome.INCONCLUSIVE,
    )
