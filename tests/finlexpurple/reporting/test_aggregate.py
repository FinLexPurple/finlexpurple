"""Phase 16: summary statistics are pure, code-computed, and traceable."""

from __future__ import annotations

from finlexpurple.detectors.schema import Finding, FindingStatus, Severity
from finlexpurple.reporting.aggregate import summarize


def _finding(status: FindingStatus, severity: Severity, n: int) -> Finding:
    f = Finding.new(
        vulnerability_class="sqli", method="GET", url=f"http://t/{n}", payload=f"q={n}", severity=severity
    )
    f.status = status
    return f


def test_counts_and_verified_percent_are_exact() -> None:
    findings = [
        _finding(FindingStatus.VERIFIED, Severity.CRITICAL, 1),
        _finding(FindingStatus.VERIFIED, Severity.HIGH, 2),
        _finding(FindingStatus.REPORTED, Severity.MEDIUM, 3),
        _finding(FindingStatus.HUMAN_CONFIRMED, Severity.LOW, 4),
    ]
    summary = summarize(findings)
    assert summary.total == 4
    assert summary.verified == 2
    assert summary.verified_percent == 50.0  # 2/4, computed
    assert summary.by_severity["critical"] == 1
    assert summary.by_severity["high"] == 1
    assert summary.by_status["verified"] == 2
    assert summary.by_status["human_confirmed"] == 1


def test_empty_findings_do_not_divide_by_zero() -> None:
    summary = summarize([])
    assert summary.total == 0
    assert summary.verified_percent == 0.0


def test_aggregate_module_makes_no_llm_or_provider_import() -> None:
    # A reviewer can confirm no number passes through a model: the stats module
    # imports nothing from the providers / LLM layer.
    import finlexpurple.reporting.aggregate as agg

    source = __import__("inspect").getsource(agg)
    for banned in ("providers", "anthropic", "openai", "llm", "narrative"):
        assert banned not in source
