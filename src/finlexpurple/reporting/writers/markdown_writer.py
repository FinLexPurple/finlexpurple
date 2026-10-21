"""Human-readable Markdown report (Phase 16; decisions.md §6, §23).

Renders the summary (all figures from ``aggregate.py``) and one section per
finding with its text badge, severity, agent, a reference to the raw
request/response evidence, the grounded explanation, a suggested fix, and — for
a verified finding — a reference to its signed evidence bundle (§23). Plain text
badges only; **no emoji** (§6).
"""

from __future__ import annotations

from dataclasses import dataclass

from finlexpurple.detectors.schema import Finding
from finlexpurple.reporting.aggregate import ReportSummary


@dataclass(frozen=True)
class RenderedFinding:
    """Everything the Markdown writer needs for one finding, already prepared."""

    finding: Finding
    badge: str
    narrative: str
    suggested_fix: str
    evidence_file: str
    replay_log_file: str | None = None
    bundle_file: str | None = None
    bundle_hash: str | None = None


def render_markdown(
    *,
    target: str,
    generated_at: str,
    summary: ReportSummary,
    rendered: list[RenderedFinding],
) -> str:
    """Render the full Markdown report as a string."""

    lines: list[str] = [
        "# FinLexPurple Security Report",
        "",
        f"- Target: `{target}`",
        f"- Generated: {generated_at}",
        "",
        "## Summary",
        "",
        f"- Total findings: {summary.total}",
        f"- Independently verified: {summary.verified} ({summary.verified_percent}% of findings)",
        "",
        "### Severity breakdown",
    ]
    lines += [f"- {sev}: {count}" for sev, count in summary.by_severity.items()]
    lines += ["", "### Status breakdown"]
    lines += [f"- {status}: {count}" for status, count in summary.by_status.items()]
    lines += ["", "## Findings", ""]

    if not rendered:
        lines.append("_No findings._")
    for item in rendered:
        f = item.finding
        lines += [
            f"### {item.badge} {f.vulnerability_class}",
            "",
            f"- Severity: {f.severity.value}",
            f"- Agent: {f.agent or 'n/a'}",
            f"- Request: `{f.method} {f.url}`",
            f"- Evidence: `{item.evidence_file}`",
        ]
        if item.replay_log_file:
            lines.append(f"- Replay log: `{item.replay_log_file}`")
        if item.bundle_file:
            lines.append(f"- Signed evidence bundle: `{item.bundle_file}` ({item.bundle_hash})")
        lines += [
            "",
            f"**Explanation.** {item.narrative}",
            "",
            f"**Suggested fix.** {item.suggested_fix}",
            "",
        ]
    return "\n".join(lines) + "\n"
