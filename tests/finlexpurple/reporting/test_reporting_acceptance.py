"""Phase 16 §5a acceptance: the four reporting checklist items, end to end."""

from __future__ import annotations

import json
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

from finlexpurple.detectors.schema import Finding, FindingStatus
from finlexpurple.reporting.aggregate import summarize
from finlexpurple.reporting.narrative import Explanation
from finlexpurple.reporting.output_layout import write_report

_NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def _findings() -> list[Finding]:
    v = Finding.new(vulnerability_class="sqli", method="GET", url="http://t/s", payload="q='",
                    response_snapshot="error in your SQL syntax", agent="web")
    v.status = FindingStatus.VERIFIED
    v.verification_log = "re-executed; SQL error reproduced."
    r = Finding.new(vulnerability_class="idor", method="GET", url="http://t/i", payload="id=1", agent="web")
    return [v, r]


def test_item1_every_number_traces_to_aggregate() -> None:
    findings = _findings()
    summary = summarize(findings)
    # Independently recomputed, matching aggregate exactly (no LLM path).
    assert summary.total == 2
    assert summary.verified == 1
    assert summary.verified_percent == 50.0


def test_item2_text_badges_and_0600_reports(tmp_path: Path) -> None:
    paths = write_report(_findings(), target="t", out_root=tmp_path, now=_NOW)
    md = paths.report_md.read_text()
    assert "[VERIFIED]" in md and "[REPORTED]" in md
    assert md.isascii()  # text labels, no emoji
    if sys.platform != "win32":
        assert stat.S_IMODE(paths.report_json.stat().st_mode) == 0o600


def test_item3_ungrounded_narrative_never_reaches_report(tmp_path: Path) -> None:
    fabricated = lambda fi: Explanation(text="Fabricated: the server returned XYZZY-SECRET.",
                                        quotes=["XYZZY-SECRET"])  # not in any evidence
    paths = write_report(_findings(), target="t", out_root=tmp_path, now=_NOW, explainer=fabricated)
    md = paths.report_md.read_text()
    assert "XYZZY-SECRET" not in md  # quote_grounding caught it; template used instead


def test_item4_layout_and_bundle_reference_for_verified(tmp_path: Path) -> None:
    findings = _findings()
    paths = write_report(findings, target="t", out_root=tmp_path, now=_NOW)
    # Section 9 layout:
    assert paths.report_json.is_file() and paths.report_md.is_file()
    assert paths.evidence_dir.is_dir() and paths.replay_logs_dir.is_dir()
    # report.md references the signed evidence bundle for the verified finding:
    verified = findings[0]
    bundle = paths.evidence_dir / f"{verified.finding_id}.bundle.json"
    assert bundle.is_file()
    assert f"evidence/{verified.finding_id}.bundle.json" in paths.report_md.read_text()
    assert json.loads(paths.report_json.read_text())["summary"]["verified"] == 1
