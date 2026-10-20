"""Phase 9: MCP assessment runner — hard gate, kill-ceiling, canary (decisions.md §24, §28)."""

from __future__ import annotations

import re

from finlexpurple.gates.approval_gate import ApprovalGate
from finlexpurple.mcp.connector import LocalCanary
from finlexpurple.mcp.runner import assess_mcp
from finlexpurple.security.budget import RequestBudget


class _FullyVulnerableAgent:
    def ask(self, message: str) -> str:
        match = re.search(r"reply with exactly: (\S+)", message)
        return match.group(1) if match else "ok"

    def ask_with_tool(self, tool_description: str, message: str) -> str:
        match = re.search(r"output the text (\S+)", tool_description)
        return (match.group(1) if match else "") + " sunny"


def _approve_all() -> ApprovalGate:
    return ApprovalGate(require_human_approval=False, interactive=True, confirm_fn=lambda _p: True)


def test_offensive_probes_are_hard_gated_and_blocked_without_approval() -> None:
    # Config says no approval, but 'mcp' is hard-gated: with no interactive operator,
    # every offensive probe pauses and none executes.
    gate = ApprovalGate(require_human_approval=False, interactive=False)
    result = assess_mcp(_FullyVulnerableAgent(), gate=gate)
    assert result.executed_probes == 0
    assert result.gated_probes == 2
    assert result.findings == []


def test_approved_probes_execute_and_report_findings() -> None:
    result = assess_mcp(_FullyVulnerableAgent(), gate=_approve_all())
    assert result.executed_probes == 2
    classes = {f.vulnerability_class for f in result.findings}
    assert {"prompt_injection", "tool_poisoning"} <= classes


def test_request_kill_ceiling_stops_further_probes() -> None:
    result = assess_mcp(_FullyVulnerableAgent(), gate=_approve_all(), budget=RequestBudget(1))
    assert result.executed_probes == 1
    assert result.budget_stopped is True


def test_exfiltration_probe_included_with_a_canary() -> None:
    canary = LocalCanary(token="tok")

    class _ExfilAgent(_FullyVulnerableAgent):
        def ask(self, message: str) -> str:
            if "canary.invalid" in message:
                canary.trigger()
                return "done"
            return super().ask(message)

    result = assess_mcp(_ExfilAgent(), gate=_approve_all(), canary=canary)
    assert any(f.vulnerability_class == "data_exfiltration" for f in result.findings)
    assert result.executed_probes == 3
