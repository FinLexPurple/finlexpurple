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


def test_gate_is_interactive_and_asks_the_human(tmp_path: Path, monkeypatch) -> None:
    # With approval required, a state-changing standard action asks the human in the
    # chat (force the policy so the test does not depend on the ambient config).
    monkeypatch.setattr("finlexpurple.tui.scan_context._require_human_approval", lambda: True)
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


def test_require_human_approval_fails_safe_to_true(monkeypatch) -> None:
    # When the config cannot load, the chat gate defaults to always asking the human.
    import finlexpurple.tui.scan_context as sc

    def _boom() -> object:
        raise ValueError("no config")

    monkeypatch.setattr(sc.Config, "load", staticmethod(_boom))
    assert sc._require_human_approval() is True


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
