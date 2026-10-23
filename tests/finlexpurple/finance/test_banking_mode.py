"""Phase 19a: the banking hard gate cannot be overridden by any config."""

from __future__ import annotations

import pytest

from finlexpurple.finance.banking_mode import (
    BankingSafetyError,
    gate_state_change,
    is_read_only_default,
)
from finlexpurple.gates.approval_gate import ApprovalGate, GateOutcome


def _gate(*, require_human_approval: bool, interactive: bool, confirm: bool | None = None) -> ApprovalGate:
    return ApprovalGate(
        require_human_approval=require_human_approval,
        interactive=interactive,
        confirm_fn=(lambda _p: confirm) if confirm is not None else None,
    )


def test_read_only_by_default() -> None:
    assert is_read_only_default() is True


def test_blocked_with_every_config_override_non_interactive() -> None:
    # Every override attempt: whether REQUIRE_HUMAN_APPROVAL is true OR false, a
    # banking state-changing step with no human present is PAUSED — never ALLOWED.
    for require in (True, False):
        outcome = gate_state_change(
            _gate(require_human_approval=require, interactive=False), "wire transfer"
        )
        assert outcome is GateOutcome.PAUSED
        assert outcome is not GateOutcome.ALLOWED


def test_interactive_decline_denies_never_allows() -> None:
    outcome = gate_state_change(
        _gate(require_human_approval=False, interactive=True, confirm=False), "wire transfer"
    )
    assert outcome is GateOutcome.DENIED  # a human said no; still never ALLOWED


def test_interactive_approve_requires_a_human_yes() -> None:
    outcome = gate_state_change(
        _gate(require_human_approval=False, interactive=True, confirm=True), "wire transfer"
    )
    assert outcome is GateOutcome.APPROVED  # only a human yes lets it proceed


def test_refuses_a_non_hard_gated_category() -> None:
    with pytest.raises(BankingSafetyError):
        gate_state_change(_gate(require_human_approval=False, interactive=False),
                          "transfer", category="ecommerce")
