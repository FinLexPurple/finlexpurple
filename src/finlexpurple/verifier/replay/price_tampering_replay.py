"""Price-tampering replay — charged-state confirmation (Task 2; decisions.md §6, §7, §14).

Re-executes a captured price-tampering finding's tampered request and decides, by
deterministic code over the re-executed evidence, whether the server actually
honored the manipulated price in durable state. Unit 1 surfaces the precise
outcome (previously all non-charged cases collapsed to REPORTED):

* ``REPRODUCED`` — the tampered amount is confirmed charged / persisted
  server-side (an independent in-scope read-back shows it recorded). -> VERIFIED
* ``NOT_REPRODUCED`` — the server rejected / recomputed the correct price, or the
  read-back confirms the tampered amount was **not** persisted. (Not a clean bill
  of health — only that this replay did not reproduce it.)
* ``INCONCLUSIVE`` — the tampered amount was reflected in the immediate response
  but durable state could not be confirmed (no read-back, or it could not tell).
* ``BLOCKED`` — approval for the state-changing re-execution was not granted, so
  nothing ran.
* ``NO_ENGINE`` — the replay could not run at all: no prober / gate, or a payload
  that is not a concrete ``param=value``. -> REPORTED

Re-executing a tampered request is a state-changing action, so it always routes
through the Phase 8 approval gate first and proceeds only when the gate approves
it (or, for a standard-gate category, config-allows it). The gate category is the
finding's own agent, so a Teller/Vault-origin finding is hard-gated automatically
and can never auto-run. The LLM is never consulted; all pass/fail is code, and
``reflected`` alone is deliberately never enough for ``reproduced=True``.
"""

from __future__ import annotations

from collections.abc import Callable

from finlexpurple.detectors.prober import Prober
from finlexpurple.detectors.schema import Finding
from finlexpurple.gates.approval_gate import ApprovalGate, GateAction, GateOutcome
from finlexpurple.verifier.status import ReplayOutcome, ReplayResult

# Given the finding and the tampered value, report whether the server durably
# recorded that value (True), confirmed it did NOT (False), or cannot be confirmed
# (None). A deployment wires this to an in-scope read of persisted state (a receipt
# / order-status resource); it must observe real server state, never guess.
ChargeConfirmer = Callable[[Finding, str], bool | None]

# Standard-gate default when a finding carries no agent. "cashier" is not
# hard-gated, so it still requires approval under the default-on policy but may be
# config-allowed; a hard-gated agent (teller/vault) keeps its non-overridable gate.
_DEFAULT_CATEGORY = "cashier"

# Gate outcomes under which a state-changing re-execution may proceed: APPROVED (a
# human said yes) or ALLOWED (a standard-gate config-allow, never produced for a
# hard-gated category). DENIED and PAUSED never proceed.
_PROCEED = (GateOutcome.APPROVED, GateOutcome.ALLOWED)


def replay(
    finding: Finding,
    prober: Prober | None,
    gate: ApprovalGate | None,
    charge_confirmer: ChargeConfirmer | None,
) -> ReplayResult:
    """Re-execute the tampered request behind the gate; verified only if charged."""

    if prober is None or gate is None:
        return ReplayResult(
            None, "price-tampering replay requires a prober and an approval gate; not provided.",
            outcome=ReplayOutcome.NO_ENGINE,
        )

    param, sep, value = finding.payload.partition("=")
    if not sep or not value:
        return ReplayResult(
            None,
            f"price-tampering replay needs a concrete param=value payload; got {finding.payload!r}.",
            outcome=ReplayOutcome.NO_ENGINE,
        )

    category = (finding.agent or _DEFAULT_CATEGORY).strip().lower()
    outcome = gate.resolve(GateAction(
        description=f"re-execute tampered price request {finding.payload!r} against {finding.url}",
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
        finding.method, finding.url, params={param: value}, headers=finding.headers or None
    )
    if value not in response.text:
        return ReplayResult(
            False,
            f"re-executed {finding.payload!r}; server did not honor the tampered price "
            "(rejected/recomputed) — not reproduced.",
            outcome=ReplayOutcome.NOT_REPRODUCED,
        )

    # The tampered value was reflected. VERIFIED requires a confirmed durable
    # state-change — reflection alone is never sufficient; without a confirmed
    # durable charge the result is inconclusive, never verified.
    if charge_confirmer is None:
        return ReplayResult(
            None,
            f"re-executed {finding.payload!r}; tampered price reflected in the response but no "
            "durable-state read-back was available to confirm it — inconclusive.",
            outcome=ReplayOutcome.INCONCLUSIVE,
        )
    charged = charge_confirmer(finding, value)
    if charged is True:
        return ReplayResult(
            True,
            f"re-executed {finding.payload!r}; tampered price {value!r} confirmed "
            "charged/persisted server-side — exploit reproduced.",
            outcome=ReplayOutcome.REPRODUCED,
        )
    if charged is False:
        return ReplayResult(
            False,
            f"re-executed {finding.payload!r}; tampered price reflected but the in-scope read-back "
            "shows it was not persisted in durable state — not reproduced.",
            outcome=ReplayOutcome.NOT_REPRODUCED,
        )
    return ReplayResult(
        None,
        f"re-executed {finding.payload!r}; tampered price reflected but durable state could "
        "not be confirmed by the read-back — inconclusive.",
        outcome=ReplayOutcome.INCONCLUSIVE,
    )
