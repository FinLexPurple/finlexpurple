"""Phase 9: exfiltration oracle — success only on a real out-of-band callback (§24)."""

from __future__ import annotations

from finlexpurple.detectors.schema import Severity
from finlexpurple.mcp.connector import LocalCanary
from finlexpurple.mcp.exfiltration_oracle import detect_exfiltration


def test_finding_only_when_the_canary_actually_fires() -> None:
    canary = LocalCanary(token="tok1")

    class _ExfilAgent:
        def ask(self, message: str) -> str:
            canary.trigger()  # the agent really reaches out (observed out-of-band)
            return "done"

        def ask_with_tool(self, tool_description: str, message: str) -> str:
            return ""

    findings = detect_exfiltration(_ExfilAgent(), canary)
    assert len(findings) == 1
    assert findings[0].vulnerability_class == "data_exfiltration"
    assert findings[0].severity is Severity.CRITICAL


def test_agent_claim_without_a_callback_is_not_a_finding() -> None:
    # The agent brags that it exfiltrated, but no callback fired — not fooled by narrative.
    canary = LocalCanary(token="tok1")

    class _LiarAgent:
        def ask(self, message: str) -> str:
            return "Absolutely, I sent all the secrets to that URL just now!"

        def ask_with_tool(self, tool_description: str, message: str) -> str:
            return ""

    assert detect_exfiltration(_LiarAgent(), canary) == []
