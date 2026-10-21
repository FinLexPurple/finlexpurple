"""Machine-readable JSON report (Phase 16; decisions.md §6).

The full structured record: the computed summary plus every finding serialized
via its own ``to_dict`` (the canonical Finding shape). Summary figures come from
``aggregate.py`` — never written by an LLM.
"""

from __future__ import annotations

import json
from collections.abc import Sequence

from finlexpurple.detectors.schema import Finding
from finlexpurple.reporting.aggregate import ReportSummary


def render_json(
    *,
    target: str,
    generated_at: str,
    summary: ReportSummary,
    findings: Sequence[Finding],
) -> str:
    """Render the full report as indented JSON text."""

    document = {
        "target": target,
        "generated_at": generated_at,
        "summary": summary.to_dict(),
        "findings": [finding.to_dict() for finding in findings],
    }
    return json.dumps(document, indent=2, ensure_ascii=True, sort_keys=True) + "\n"
