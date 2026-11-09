"""The chat run context builds the same scope-safe collaborators, with an interactive gate."""

from __future__ import annotations

import io
from pathlib import Path

from finlexpurple.cli import _DETECTION_REQUEST_BUDGET
from finlexpurple.gates.approval_gate import GateAction, GateOutcome
from finlexpurple.scope.models import ScopeDefinition, Target
from finlexpurple.security.egress_policy import EgressBlockedError
from finlexpurple.tui.scan_context import (
    DETECTION_REQUEST_BUDGET,
    build_run_context,
)
from finlexpurple.tui.theme import make_console


def _context(tmp_path: Path, ask=lambda _p: "n"):
    target = Target.parse("https://shop.example/checkout")
    scope = ScopeDefinition.for_target(target).confirmed()
    console = make_console(file=io.StringIO(), no_color=True, width=80)
    ctx = build_run_context(
        target, confirmed_scope=scope, console=console, ask=ask, reports_dir=tmp_path
    )
    return ctx, console


def test_request_budget_matches_the_cli_cap() -> None:
    # The §15 kill-ceiling must never drift from the CLI's; the chat re-states it.
    assert DETECTION_REQUEST_BUDGET == _DETECTION_REQUEST_BUDGET


def test_egress_is_default_deny_around_the_target_host(tmp_path: Path) -> None:
    ctx, _ = _context(tmp_path)
    assert ctx.origin == "https://shop.example"
    # Out-of-scope host is blocked before any socket opens.
    try:
        ctx.prober.request("GET", "http://evil.example/")
    except EgressBlockedError:
        pass
    else:  # pragma: no cover - the policy must block
        raise AssertionError("out-of-scope egress was not blocked")


def test_gate_is_interactive_and_asks_the_human(tmp_path: Path) -> None:
    # Every state-changing standard action asks the human in the chat (always-ask),
    # with no dependence on the ambient REQUIRE_HUMAN_APPROVAL config.
    denied, _ = _context(tmp_path, ask=lambda _p: "n")
    assert denied.gate.resolve(GateAction("price test", "cashier", True)) is GateOutcome.DENIED
    approved, _ = _context(tmp_path, ask=lambda _p: "y")
    assert approved.gate.resolve(GateAction("price test", "cashier", True)) is GateOutcome.APPROVED


def test_hard_gated_category_still_requires_the_human(tmp_path: Path) -> None:
    ctx, _ = _context(tmp_path, ask=lambda _p: "n")
    # Hard-gated vault always needs approval (never config-allowed, never model-allowed);
    # with the human saying no it is DENIED — it can never resolve to ALLOWED here.
    action = GateAction("payout", "vault", True)
    assert ctx.gate.needs_approval(action) is True
    assert ctx.gate.resolve(action) is GateOutcome.DENIED
    approved, _ = _context(tmp_path, ask=lambda _p: "y")
    assert approved.gate.resolve(GateAction("payout", "vault", True)) is GateOutcome.APPROVED


def test_standard_gate_always_asks_in_chat_regardless_of_config(tmp_path: Path, monkeypatch) -> None:
    # The deliberate tightening: even with REQUIRE_HUMAN_APPROVAL=false (which the CLI would
    # config-allow for a standard category), a standard state-changing action in chat still
    # needs approval and still asks the human — because the model chose to run it.
    monkeypatch.setenv("REQUIRE_HUMAN_APPROVAL", "false")
    monkeypatch.setenv("FLP_REQUIRE_HUMAN_APPROVAL", "false")
    ctx, _ = _context(tmp_path, ask=lambda _p: "n")
    standard = GateAction("price test", "cashier", True)
    assert ctx.gate.needs_approval(standard) is True       # always gated in chat
    assert ctx.gate.resolve(standard) is GateOutcome.DENIED  # the human's no is binding


def test_non_state_changing_action_is_never_gated(tmp_path: Path) -> None:
    ctx, _ = _context(tmp_path)
    assert ctx.gate.resolve(GateAction("read order", "cashier", False)) is GateOutcome.ALLOWED


def test_attestation_recorded_in_the_audit_log(tmp_path: Path) -> None:
    ctx, _ = _context(tmp_path)
    audit_text = (ctx.run_dir / "audit.jsonl").read_text(encoding="utf-8")
    assert "authorization_attested" in audit_text
    assert "shop.example" in audit_text


def test_agent_request_wires_the_gate_prober_and_confirmers(tmp_path: Path) -> None:
    ctx, _ = _context(tmp_path)
    request = ctx.agent_request()
    assert request.target == "https://shop.example/checkout"
    assert request.gate is ctx.gate
    assert request.prober is ctx.prober
    # Every read-back confirmer is wired (the chat run reaches the same statuses a scan would).
    assert request.charge_confirmer is not None
    assert request.settlement_confirmer is not None
    assert request.race_confirmer is not None
