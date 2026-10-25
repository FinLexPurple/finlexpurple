"""The banking hard-gate framework (Phase 19a; decisions.md §7, §14, §3).

Banking (Teller) is the highest-risk category: read-only / non-destructive by
default, and **any** state-changing step must route through the Phase 8 approval
gate, which — for a hard-gated category — can never be turned off by a config
value, environment variable, or plan tier. Autonomous exploitation of a banking
target is never permitted on any tier.

``gate_state_change`` is the single choke point every banking state-changing step
must pass through. It refuses to run outside the hard gate, and treats an
``ALLOWED`` outcome for a hard-gated state-changing action as a bug and raises —
so even a gate regression cannot let a banking action through without a human.
"""

from __future__ import annotations

from finlexpurple.gates.approval_gate import ApprovalGate, GateAction, GateOutcome, is_hard_gated

# Hard-gated categories (see approval_gate.HARD_GATED_CATEGORIES). Teller (banking)
# and Vault (crypto/Web3) share the identical non-overridable rule — crypto
# transactions are irreversible in the same way core-banking actions are (§14).
BANKING_CATEGORY = "teller"
VAULT_CATEGORY = "vault"


class BankingSafetyError(RuntimeError):
    """A banking state-changing step was about to run without the hard gate."""


def is_read_only_default() -> bool:
    """Banking testing is read-only/non-destructive by default — always True."""

    return True


def gate_state_change(
    gate: ApprovalGate, description: str, *, category: str = BANKING_CATEGORY
) -> GateOutcome:
    """Route a banking state-changing step through the non-overridable hard gate.

    Raises :class:`BankingSafetyError` if the category is not hard-gated, or if
    the gate ever returns ``ALLOWED`` for a hard-gated state-changing action
    (which must be impossible). Otherwise returns the gate's outcome — APPROVED
    only when a human said yes, DENIED when a human said no, PAUSED when no human
    is present. It can never return ALLOWED.
    """

    if not is_hard_gated(category):
        raise BankingSafetyError(
            f"{category!r} is not hard-gated; refusing to run a banking state-changing step "
            "outside the hard gate."
        )
    outcome = gate.resolve(GateAction(description=description, category=category, state_changing=True))
    if outcome is GateOutcome.ALLOWED:
        raise BankingSafetyError(
            "the approval gate returned ALLOWED for a banking state-changing step; refusing to proceed."
        )
    return outcome
