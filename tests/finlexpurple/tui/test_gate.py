"""The chat gate prompt asks the human and never weakens the approval gate (decision D)."""

from __future__ import annotations

import io

from finlexpurple.gates.approval_gate import ApprovalGate, GateAction, GateOutcome
from finlexpurple.tui.gate import make_gate_confirm
from finlexpurple.tui.theme import make_console


def _gate(answer: str, *, interactive: bool = True, require: bool = True) -> ApprovalGate:
    console = make_console(file=io.StringIO(), no_color=True, width=72)
    return ApprovalGate(require, interactive=interactive, confirm_fn=make_gate_confirm(console, lambda _p: answer))


def test_explicit_yes_approves_a_standard_action() -> None:
    assert _gate("y").resolve(GateAction("refund re-send", "cashier", True)) is GateOutcome.APPROVED
    assert _gate("yes").resolve(GateAction("refund re-send", "cashier", True)) is GateOutcome.APPROVED


def test_anything_else_denies_fail_safe() -> None:
    for answer in ("", "n", "no", "maybe", "approve please"):
        assert _gate(answer).resolve(GateAction("x", "cashier", True)) is GateOutcome.DENIED


def test_non_state_changing_is_never_gated() -> None:
    # confirm must not even be consulted; a read action is ALLOWED.
    assert _gate("n").resolve(GateAction("read order", "cashier", False)) is GateOutcome.ALLOWED


def test_hard_gated_category_cannot_be_config_allowed() -> None:
    # Even with require_human_approval False, a vault action is not ALLOWED; with no human
    # present it PAUSES — the agent can never make it run on its own.
    paused = _gate("y", interactive=False, require=False).resolve(GateAction("payout", "vault", True))
    assert paused is GateOutcome.PAUSED


def test_hard_gated_interactive_still_requires_the_human() -> None:
    # Interactive: the human is asked; a no denies. The gate (not this UI) guarantees the
    # category is always asked and never auto-allowed.
    assert _gate("no").resolve(GateAction("payout", "vault", True)) is GateOutcome.DENIED
    assert _gate("y").resolve(GateAction("payout", "vault", True)) is GateOutcome.APPROVED
