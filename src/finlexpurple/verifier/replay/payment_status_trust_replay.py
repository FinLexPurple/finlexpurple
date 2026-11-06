"""Payment-status-trust replay — re-set + durable-paid confirmation (Unit 2.3).

Re-sends a captured ``payment_status_trust`` finding's client-controlled status
(e.g. ``status=paid``) to the order's own status endpoint — distinct from the
webhook callback path — and decides, by deterministic code, whether the server
durably trusted the client-set status:

* ``REPRODUCED`` — the status set is accepted (HTTP 2xx) **and** an independent
  in-scope read-back confirms the order is durably marked with that status (e.g.
  ``paid``) without any real settlement. -> VERIFIED
* ``NOT_REPRODUCED`` — the server rejected it (it does not trust a client status),
  or it accepted it but the read-back shows the order was **not** marked. (Not
  "the app is safe" — only that this replay did not reproduce it.)
* ``INCONCLUSIVE`` — accepted but durable state could not be confirmed (no
  read-back available, or it could not tell).
* ``BLOCKED`` — approval for the state-changing re-execution was not granted.
* ``NO_ENGINE`` — the replay could not run (no prober / gate, or no captured
  ``param=status`` to re-send). -> REPORTED

Setting an order's payment status is a state-changing action, so it always routes
through the Phase 8 approval gate first; the gate category is the finding's own
agent, so a Teller/Vault-origin finding is hard-gated and can never auto-run. The
LLM is never consulted; acceptance alone is never enough for ``REPRODUCED`` — a
confirmed durable paid-status is required, and the confirmer must read REAL
in-scope order state, never synthesize a paid signal.
"""

from __future__ import annotations

from collections.abc import Callable

from finlexpurple.detectors.prober import Prober, ProbeResponse
from finlexpurple.detectors.schema import Finding
from finlexpurple.gates.approval_gate import ApprovalGate, GateAction, GateOutcome
from finlexpurple.verifier.status import ReplayOutcome, ReplayResult

# Given the captured finding and the client-set status value, report whether
# durable order state now shows that status (True), confirms it does NOT (False),
# or cannot be confirmed (None). A deployment wires this to a real in-scope read
# of the persisted order (an order-status oracle); it must observe real server
# state, never guess.
PaymentStatusConfirmer = Callable[[Finding, str], bool | None]

# Standard-gate default when a finding carries no agent (mirrors price_tampering).
_DEFAULT_CATEGORY = "cashier"

# Gate outcomes under which a state-changing re-execution may proceed.
_PROCEED = (GateOutcome.APPROVED, GateOutcome.ALLOWED)


def _accepted(response: ProbeResponse) -> bool:
    """The server appears to accept the client-set status: a 2xx status."""

    return 200 <= response.status_code < 300


def replay(
    finding: Finding,
    prober: Prober | None,
    gate: ApprovalGate | None,
    payment_status_confirmer: PaymentStatusConfirmer | None,
) -> ReplayResult:
    """Re-set the captured status behind the gate; reproduced only if durably recorded."""

    if prober is None or gate is None:
        return ReplayResult(
            None, "payment-status replay requires a prober and an approval gate; not provided.",
            outcome=ReplayOutcome.NO_ENGINE,
        )
    if "=" not in finding.payload:
        return ReplayResult(
            None,
            "payment-status replay needs a captured 'param=status' to re-send; none present.",
            outcome=ReplayOutcome.NO_ENGINE,
        )
    param, _, status = finding.payload.partition("=")

    category = (finding.agent or _DEFAULT_CATEGORY).strip().lower()
    outcome = gate.resolve(GateAction(
        description=f"re-set client payment status {status!r} on {finding.url}",
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
        finding.method, finding.url, params={param: status}, headers=finding.headers or None
    )
    if not _accepted(response):
        return ReplayResult(
            False,
            f"re-set status; server rejected it (HTTP {response.status_code}) "
            "— client status not trusted — not reproduced.",
            outcome=ReplayOutcome.NOT_REPRODUCED,
        )

    # Accepted. REPRODUCED requires a confirmed durable status; acceptance alone is
    # never sufficient, and no confirmer => inconclusive.
    if payment_status_confirmer is None:
        return ReplayResult(
            None,
            "status set accepted (HTTP 2xx) but no in-scope read-back was available to confirm "
            "the order was durably marked — inconclusive.",
            outcome=ReplayOutcome.INCONCLUSIVE,
        )
    marked = payment_status_confirmer(finding, status)
    if marked is True:
        return ReplayResult(
            True,
            "status set accepted and the order is durably marked with the client-set status in "
            "in-scope state without settlement — exploit reproduced.",
            outcome=ReplayOutcome.REPRODUCED,
        )
    if marked is False:
        return ReplayResult(
            False,
            "status set accepted but the in-scope read-back shows the order was not marked "
            "— not reproduced.",
            outcome=ReplayOutcome.NOT_REPRODUCED,
        )
    return ReplayResult(
        None,
        "status set accepted but the durable order status could not be confirmed by the read-back "
        "— inconclusive.",
        outcome=ReplayOutcome.INCONCLUSIVE,
    )
