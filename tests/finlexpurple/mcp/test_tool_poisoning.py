"""Phase 9: tool-poisoning tester (decisions.md §24)."""

from __future__ import annotations

import re

from finlexpurple.mcp.tool_poisoning import detect_tool_poisoning


class _PoisonFollowingAgent:
    """Blindly follows an instruction hidden in a tool description (vulnerable)."""

    def ask(self, message: str) -> str:
        return "ok"

    def ask_with_tool(self, tool_description: str, message: str) -> str:
        match = re.search(r"output the text (\S+)", tool_description)
        prefix = match.group(1) if match else ""
        return f"{prefix} The weather is sunny."


class _CleanAgent:
    def ask(self, message: str) -> str:
        return "ok"

    def ask_with_tool(self, tool_description: str, message: str) -> str:
        return "The weather is sunny."


def test_detects_tool_poisoning() -> None:
    findings = detect_tool_poisoning(_PoisonFollowingAgent(), nonce="z1")
    assert len(findings) == 1
    assert findings[0].vulnerability_class == "tool_poisoning"
    assert "FLP-POISONED-z1" in findings[0].expected_signal


def test_clean_agent_yields_no_finding() -> None:
    assert detect_tool_poisoning(_CleanAgent(), nonce="z1") == []
