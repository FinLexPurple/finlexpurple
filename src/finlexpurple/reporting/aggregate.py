"""Code-computed report statistics (Phase 16; decisions.md §6).

Every number in a report comes from here — a pure function over the structured
findings, with **no LLM call anywhere**. A reviewer can read this one file and
confirm that totals, the severity breakdown, and the "percent independently
verified" figure (the product's core credibility signal, §6) are arithmetic over
the data, never written or estimated by a model.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field

from finlexpurple.detectors.schema import Finding, FindingStatus, Severity

# Stable display order for the severity breakdown.
_SEVERITY_ORDER = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
)


@dataclass(frozen=True)
class ReportSummary:
    """Summary statistics for a set of findings — all computed, never LLM-written."""

    total: int
    by_severity: dict[str, int] = field(default_factory=dict)
    by_status: dict[str, int] = field(default_factory=dict)
    verified: int = 0
    verified_percent: float = 0.0

    def to_dict(self) -> dict[str, object]:
        return {
            "total": self.total,
            "by_severity": dict(self.by_severity),
            "by_status": dict(self.by_status),
            "verified": self.verified,
            "verified_percent": self.verified_percent,
        }


def summarize(findings: Sequence[Finding]) -> ReportSummary:
    """Compute the report summary purely from the findings (no LLM involved)."""

    total = len(findings)
    by_severity = {sev.value: 0 for sev in _SEVERITY_ORDER}
    by_status = {status.value: 0 for status in FindingStatus}
    for finding in findings:
        by_severity[finding.severity.value] = by_severity.get(finding.severity.value, 0) + 1
        by_status[finding.status.value] = by_status.get(finding.status.value, 0) + 1
    verified = by_status.get(FindingStatus.VERIFIED.value, 0)
    # Rounded to one decimal; 0.0 when there are no findings (no division by zero).
    verified_percent = round(100.0 * verified / total, 1) if total else 0.0
    return ReportSummary(
        total=total,
        by_severity=by_severity,
        by_status=by_status,
        verified=verified,
        verified_percent=verified_percent,
    )
