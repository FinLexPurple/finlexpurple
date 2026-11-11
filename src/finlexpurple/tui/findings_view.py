"""Finding cards and the scan summary table for chat (chat-only; imports rich).

How a scan's results are shown in the conversation: one compact **card** per finding (a
status badge, severity, class, the probed request, and an honest one-line verdict) and a
**KV summary table** (target, what was scanned, and the by-status breakdown). Pure rendering,
so each piece unit-tests by rendering to a string.

The verdict wording is deliberately exact: only ``verified`` means independently reproduced,
and ``inconclusive`` / ``not_reproduced`` are never dressed up as a clean bill of health.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import TYPE_CHECKING

from rich.box import MINIMAL
from rich.console import Group, RenderableType
from rich.table import Table
from rich.text import Text

if TYPE_CHECKING:
    from finlexpurple.detectors.schema import Finding

# status value -> (badge label, theme style). Only verified/human_confirmed are "good news".
_BADGE: dict[str, tuple[str, str]] = {
    "verified": ("VERIFIED", "flp.verified"),
    "human_confirmed": ("CONFIRMED", "flp.verified"),
    "reported": ("REPORTED", "flp.accent"),
    "inconclusive": ("INCONCLUSIVE", "flp.muted"),
    "not_reproduced": ("NOT REPRODUCED", "flp.muted"),
    "blocked": ("BLOCKED", "flp.blocked"),
}

# status value -> the honest one-line verdict shown under the card.
_VERDICT: dict[str, str] = {
    "verified": "reproduced by deterministic replay",
    "human_confirmed": "confirmed by a human reviewer",
    "reported": "candidate — not independently verified",
    "inconclusive": "replayed; durable impact could not be confirmed",
    "not_reproduced": "replayed and did not reproduce (not 'absent')",
    "blocked": "replay blocked by the approval gate",
}

# The order statuses appear in the summary breakdown (most-significant first).
_STATUS_ORDER = ("verified", "human_confirmed", "reported", "inconclusive", "not_reproduced", "blocked")


def _badge(status_value: str) -> tuple[str, str]:
    return _BADGE.get(status_value, (status_value.upper(), "flp.muted"))


def finding_card(finding: Finding) -> RenderableType:
    """One compact card for a finding: a colored left bar + badge/class, the request, a verdict."""

    label, style = _badge(finding.status.value)
    verdict = _VERDICT.get(finding.status.value, "")
    body = Text()
    body.append(label, style=f"bold {style}")
    body.append(f"  ·  {finding.severity.value}  ·  ", style="flp.muted")
    body.append(finding.vulnerability_class, style="flp.text")
    body.append("\n")
    body.append(f"{finding.method} {finding.url}", style="flp.muted")
    if verdict:
        body.append("\n")
        body.append(f"↪ {verdict}", style=style)
        if finding.agent:
            body.append(f"  · {finding.agent}", style="flp.muted")

    bar = Text("\n".join("▌" for _ in range(body.plain.count("\n") + 1)), style=style)
    grid = Table.grid(padding=(0, 1))
    grid.add_column(no_wrap=True)
    grid.add_column()
    grid.add_row(bar, body)
    return grid


def finding_cards(findings: Sequence[Finding]) -> RenderableType:
    """A group of finding cards, most-significant status first (verified at the top)."""

    order = {status: index for index, status in enumerate(_STATUS_ORDER)}
    ranked = sorted(findings, key=lambda f: order.get(f.status.value, len(order)))
    return Group(*(finding_card(f) for f in ranked))


def status_breakdown(findings: Sequence[Finding]) -> str:
    """A compact 'N verified · M reported · …' breakdown in significance order."""

    counts: dict[str, int] = {}
    for finding in findings:
        counts[finding.status.value] = counts.get(finding.status.value, 0) + 1
    parts = [f"{counts[s]} {s}" for s in _STATUS_ORDER if counts.get(s)]
    return " · ".join(parts) or "none"


def summary_table(rows: Sequence[tuple[str, str]], findings: Sequence[Finding]) -> Table:
    """A KV summary table: the caller's rows (target, what was scanned) + the findings breakdown."""

    table = Table(box=MINIMAL, show_header=False, pad_edge=False, expand=False)
    table.add_column(justify="right", style="flp.accent", no_wrap=True)
    table.add_column(style="flp.text")
    for label, value in rows:
        table.add_row(label, value)
    table.add_row("findings", f"{len(findings)}  ({status_breakdown(findings)})")
    return table
