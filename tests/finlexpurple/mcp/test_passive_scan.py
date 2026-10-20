"""Phase 9: passive mcp-scan wrap — parse real JSON, never paraphrase (decisions.md §20)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from finlexpurple.mcp.passive_scan import MCPScanError, parse_mcp_scan_output, run_passive_scan
from finlexpurple.tools.registry import ExternalTool

# NOTE: provisional sample shape — the real mcp-scan JSON must be confirmed
# against the installed tool (see the module docstring).
_SAMPLE = {
    "issues": [
        {
            "type": "tool_poisoning",
            "id": "MCP-001",
            "target": "server-a",
            "title": "Unsigned tool description",
            "severity": "high",
        }
    ]
}


def test_parse_normalizes_to_findings_verbatim() -> None:
    findings = parse_mcp_scan_output(json.dumps(_SAMPLE))
    assert len(findings) == 1
    finding = findings[0]
    assert finding.vulnerability_class == "mcp_tool_poisoning"
    assert finding.severity.value == "high"
    assert "Unsigned tool description" in finding.expected_signal
    assert finding.agent == "mcp"
    # Evidence is the tool's own JSON, not a paraphrase.
    assert "MCP-001" in (finding.response_snapshot or "")


def test_invalid_json_raises() -> None:
    with pytest.raises(MCPScanError, match="valid JSON"):
        parse_mcp_scan_output("not json")


def test_unexpected_shape_raises() -> None:
    with pytest.raises(MCPScanError, match="Unexpected"):
        parse_mcp_scan_output(json.dumps({"issues": "nope"}))


def test_missing_tool_skips_cleanly(tmp_path: Path) -> None:
    absent = ExternalTool("mcp-scan", "finlexpurple-absent-mcp-scan", "absent")
    assert run_passive_scan(tmp_path / "config.json", tool=absent) == []
