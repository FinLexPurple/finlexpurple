"""Passive MCP-configuration scan by wrapping mcp-scan (Phase 9; decisions.md §20).

This is the one place Phase 9 wraps OSS: it runs ``mcp-scan`` through the
hardened sandbox and **normalizes its real JSON output into Finding objects**,
copying the tool's own structured fields verbatim — it never paraphrases a
scanner's prose into a finding. If ``mcp-scan`` is not installed, the scan is
skipped cleanly (empty result), never faked.

PROVISIONAL (flagged): mcp-scan is not installed in this build environment, so
the exact JSON field names and CLI invocation below are a best-effort mapping
and must be verified against a real ``mcp-scan`` run before being relied upon.
The parser is defensive and fails loudly on an unexpected shape rather than
guessing.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path

from finlexpurple.detectors.schema import Finding, Severity
from finlexpurple.tools.registry import TOOL_REGISTRY, ExternalTool

logger = logging.getLogger(__name__)
_MAX_SNAPSHOT = 2000

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
    "informational": Severity.INFO,
}


class MCPScanError(RuntimeError):
    """mcp-scan produced output that could not be parsed or failed to run."""


def _severity(value: object) -> Severity:
    return _SEVERITY_MAP.get(str(value).strip().lower(), Severity.MEDIUM)


def parse_mcp_scan_output(raw: str, *, agent: str = "mcp") -> list[Finding]:
    """Normalize mcp-scan's JSON into Finding objects without paraphrasing.

    Reads fields directly from the tool's structured output and stores the raw
    issue object as the evidence snapshot. Raises :class:`MCPScanError` on
    invalid JSON or an unexpected shape.
    """

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise MCPScanError("mcp-scan did not emit valid JSON.") from exc
    issues = data.get("issues", []) if isinstance(data, dict) else data
    if not isinstance(issues, list):
        raise MCPScanError("Unexpected mcp-scan JSON shape (expected a list of issues).")

    findings: list[Finding] = []
    for issue in issues:
        if not isinstance(issue, dict):
            raise MCPScanError("Unexpected mcp-scan issue entry (expected an object).")
        issue_type = str(issue.get("type") or issue.get("check") or "issue")
        findings.append(
            Finding.new(
                vulnerability_class=f"mcp_{issue_type}",
                method="MCP",
                url=str(issue.get("target") or issue.get("server") or "mcp://config"),
                payload=str(issue.get("id") or issue_type),
                # Verbatim tool data as evidence — not a paraphrase.
                response_snapshot=json.dumps(issue, sort_keys=True)[:_MAX_SNAPSHOT],
                expected_signal=str(issue.get("title") or issue.get("message") or issue_type),
                severity=_severity(issue.get("severity")),
                agent=agent,
            )
        )
    return findings


def run_passive_scan(
    config_path: Path,
    *,
    tool: ExternalTool | None = None,
    timeout: float = 120,
    agent: str = "mcp",
) -> list[Finding]:
    """Run mcp-scan on an MCP config and return normalized findings (or [] if absent)."""

    resolved = tool or TOOL_REGISTRY["mcp-scan"]
    if not resolved.is_installed():
        logger.warning("mcp-scan is not installed; skipping the passive MCP configuration scan.")
        return []
    result = resolved.run(["scan", "--json", str(config_path)], timeout=timeout)
    if result.timed_out:
        raise MCPScanError("mcp-scan timed out.")
    # mcp-scan may use exit 1 to signal that issues were found; anything else is an error.
    if result.returncode not in (0, 1):
        raise MCPScanError(f"mcp-scan failed (exit {result.returncode}).")
    return parse_mcp_scan_output(result.stdout, agent=agent)
