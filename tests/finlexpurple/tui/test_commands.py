"""Direct slash-commands run the same gated ops the dispatcher uses, with no model call."""

from __future__ import annotations

import io

from finlexpurple.tui.commands import run_direct_command
from finlexpurple.tui.theme import make_console


def _run(line: str, *, ask=lambda _p: "n"):
    console = make_console(file=io.StringIO(), no_color=True, force_terminal=True, width=90)
    result = run_direct_command(line, console=console, ask=ask)
    return result, console.file.getvalue()


def test_agents_lists_the_roster_directly() -> None:
    result, out = _run("/agents")
    assert result.handled
    assert "cashier" in out and "teller" in out
    assert "/agents" in result.transcript


def test_scan_runs_through_scope_confirmation_and_is_fail_safe() -> None:
    # The human (ask) denies scope: the direct scan confirms nothing is scanned — same gate
    # as the autonomous path, no model call involved.
    result, out = _run("/scan https://shop.example/checkout", ask=lambda _p: "n")
    assert result.handled
    assert "scope not confirmed" in out
    assert "/scan https://shop.example/checkout" in result.transcript


def test_run_requires_agent_and_target() -> None:
    result, out = _run("/run cashier")  # missing target
    assert result.handled and "usage: /run" in out


def test_scan_requires_a_url() -> None:
    result, out = _run("/scan")
    assert result.handled and "usage: /scan" in out


def test_verify_reports_unreadable_bundle() -> None:
    result, out = _run("/verify /nonexistent/bundle.json")
    assert result.handled and "could not read bundle" in out


def test_unknown_slash_is_not_handled() -> None:
    result, _ = _run("/wat")
    assert result.handled is False
