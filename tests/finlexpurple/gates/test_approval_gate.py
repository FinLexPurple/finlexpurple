"""Phase 8: the human-in-the-loop approval gate and the non-overridable hard rule."""

from __future__ import annotations

from pathlib import Path

import pytest

from finlexpurple.gates.approval_gate import (
    HARD_GATED_CATEGORIES,
    ApprovalGate,
    GateAction,
    GateOutcome,
    is_hard_gated,
)
from finlexpurple.security.audit_log import AuditLog


def test_non_state_changing_is_never_gated() -> None:
    gate = ApprovalGate(require_human_approval=True, interactive=False)
    action = GateAction("read a page", "generic", state_changing=False)
    assert gate.needs_approval(action) is False
    assert gate.resolve(action) is GateOutcome.ALLOWED


@pytest.mark.parametrize("category", sorted(HARD_GATED_CATEGORIES))
def test_hard_gated_always_needs_approval_even_with_config_off(category: str) -> None:
    # Config says no approval needed, but hard-gated categories ignore config.
    gate = ApprovalGate(require_human_approval=False, interactive=False)
    action = GateAction("transfer funds", category, state_changing=True)
    assert is_hard_gated(category)
    assert gate.needs_approval(action) is True
    # With no interactive operator it PAUSES — it never auto-ALLOWs.
    assert gate.resolve(action) is GateOutcome.PAUSED


def test_hard_gated_cannot_be_auto_allowed_interactively_without_yes() -> None:
    # Even interactive, a 'no' is DENIED and a 'yes' is APPROVED — never ALLOWED.
    denied = ApprovalGate(require_human_approval=False, interactive=True, confirm_fn=lambda _p: False)
    assert denied.resolve(GateAction("x", "vault", state_changing=True)) is GateOutcome.DENIED
    approved = ApprovalGate(require_human_approval=False, interactive=True, confirm_fn=lambda _p: True)
    assert approved.resolve(GateAction("x", "vault", state_changing=True)) is GateOutcome.APPROVED


def test_generic_state_changing_follows_config() -> None:
    off = ApprovalGate(require_human_approval=False, interactive=False)
    assert off.needs_approval(GateAction("x", "generic", state_changing=True)) is False
    assert off.resolve(GateAction("x", "generic", state_changing=True)) is GateOutcome.ALLOWED
    on = ApprovalGate(require_human_approval=True, interactive=False)
    assert on.needs_approval(GateAction("x", "generic", state_changing=True)) is True
    assert on.resolve(GateAction("x", "generic", state_changing=True)) is GateOutcome.PAUSED


def test_decisions_are_recorded_in_the_audit_log(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    gate = ApprovalGate(require_human_approval=False, interactive=False, audit_log=log)
    gate.resolve(GateAction("wire transfer", "teller", state_changing=True))
    assert log.verify() is True
    entry = (tmp_path / "audit.jsonl").read_text(encoding="utf-8")
    assert "approval_decision" in entry and "teller" in entry and "paused" in entry


def test_interactive_without_confirm_fn_is_a_programming_error() -> None:
    gate = ApprovalGate(require_human_approval=True, interactive=True)
    with pytest.raises(RuntimeError, match="no confirm function"):
        gate.resolve(GateAction("x", "generic", state_changing=True))
