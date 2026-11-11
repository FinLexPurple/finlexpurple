"""Finding cards show an honest badge + verdict, and the summary table breaks down by status."""

from __future__ import annotations

import io

from finlexpurple.detectors.schema import Finding, FindingStatus, Severity
from finlexpurple.tui.findings_view import (
    finding_card,
    finding_cards,
    status_breakdown,
    summary_table,
)
from finlexpurple.tui.theme import make_console


def _finding(vuln: str, status: FindingStatus, *, severity=Severity.HIGH, agent="cashier") -> Finding:
    f = Finding.new(vulnerability_class=vuln, method="GET", url=f"http://t/{vuln}",
                    payload="p", severity=severity, agent=agent)
    f.status = status
    return f


def _render(renderable, *, width: int = 90) -> str:
    console = make_console(file=io.StringIO(), no_color=True, force_terminal=True, width=width)
    console.print(renderable)
    return console.file.getvalue()


def test_verified_card_badge_request_and_honest_verdict() -> None:
    out = _render(finding_card(_finding("price_tampering", FindingStatus.VERIFIED)))
    assert "VERIFIED" in out
    assert "price_tampering" in out
    assert "GET http://t/price_tampering" in out
    assert "reproduced by deterministic replay" in out
    assert "cashier" in out


def test_inconclusive_and_reported_verdicts_are_not_dressed_up() -> None:
    inc = _render(finding_card(_finding("webhook_bypass", FindingStatus.INCONCLUSIVE)))
    assert "INCONCLUSIVE" in inc and "could not be confirmed" in inc
    rep = _render(finding_card(_finding("xss", FindingStatus.REPORTED)))
    assert "REPORTED" in rep and "not independently verified" in rep


def test_blocked_and_not_reproduced_wording() -> None:
    blk = _render(finding_card(_finding("race_condition", FindingStatus.BLOCKED)))
    assert "BLOCKED" in blk and "blocked by the approval gate" in blk
    nr = _render(finding_card(_finding("sqli", FindingStatus.NOT_REPRODUCED)))
    assert "NOT REPRODUCED" in nr and "did not reproduce" in nr


def test_cards_rank_verified_first() -> None:
    findings = [
        _finding("a", FindingStatus.REPORTED),
        _finding("b", FindingStatus.VERIFIED),
        _finding("c", FindingStatus.INCONCLUSIVE),
    ]
    out = _render(finding_cards(findings))
    assert out.index("VERIFIED") < out.index("REPORTED") < out.index("INCONCLUSIVE")


def test_status_breakdown_counts_in_significance_order() -> None:
    findings = [
        _finding("a", FindingStatus.REPORTED),
        _finding("b", FindingStatus.REPORTED),
        _finding("c", FindingStatus.VERIFIED),
    ]
    assert status_breakdown(findings) == "1 verified · 2 reported"
    assert status_breakdown([]) == "none"


def test_summary_table_shows_rows_and_findings_breakdown() -> None:
    findings = [_finding("a", FindingStatus.VERIFIED), _finding("b", FindingStatus.REPORTED)]
    out = _render(summary_table([("target", "http://t/"), ("scanned", "3 endpoints")], findings))
    assert "target" in out and "http://t/" in out
    assert "scanned" in out and "3 endpoints" in out
    assert "findings" in out and "2" in out and "1 verified" in out and "1 reported" in out
