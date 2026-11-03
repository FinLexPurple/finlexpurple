"""Phase 16: JSON and Markdown writers render the summary and findings."""

from __future__ import annotations

import json

from finlexpurple.detectors.schema import Finding, FindingStatus
from finlexpurple.reporting.aggregate import summarize
from finlexpurple.reporting.writers.json_writer import render_json
from finlexpurple.reporting.writers.markdown_writer import RenderedFinding, render_markdown


def _finding() -> Finding:
    f = Finding.new(vulnerability_class="sqli", method="GET", url="http://t/s", payload="q='", agent="web")
    f.status = FindingStatus.VERIFIED
    return f


def test_json_writer_has_summary_and_findings() -> None:
    f = _finding()
    doc = json.loads(render_json(
        target="http://t/s", run_id="t-00000000-01M59ZNBK0ZKGNFAXEEP9EXSZ4",
        started_at="2026-01-01T00:00:00+00:00", generated_at="2026-01-01T00:00:01+00:00",
        summary=summarize([f]), findings=[f],
    ))
    assert doc["schema_version"] == 1
    assert doc["tool"]["name"] == "finlexpurple"
    assert doc["target"]["raw"] == "http://t/s" and doc["target"]["host"] == "t"
    assert doc["summary"]["verified"] == 1
    finding_doc = doc["findings"][0]
    assert finding_doc["vulnerability_class"] == "sqli"
    assert finding_doc["rule_id"] == "sqli"
    assert finding_doc["location"]["route_template"] == "/s"
    assert doc["rules"]["sqli"]["family"] == "web"


def test_markdown_writer_uses_text_badge_and_bundle_ref() -> None:
    f = _finding()
    rendered = [RenderedFinding(
        finding=f, badge="[VERIFIED]", narrative="why", suggested_fix="fix",
        evidence_file="evidence/x.json", replay_log_file="replay-logs/x.log",
        bundle_file="evidence/x.bundle.json", bundle_hash="sha256:abc",
    )]
    md = render_markdown(target="t", generated_at="2026-01-01T00:00:00+00:00",
                         summary=summarize([f]), rendered=rendered)
    assert "[VERIFIED]" in md
    assert "evidence/x.bundle.json" in md and "sha256:abc" in md
    assert md.isascii()  # no emoji anywhere


def test_markdown_handles_no_findings() -> None:
    md = render_markdown(target="t", generated_at="t", summary=summarize([]), rendered=[])
    assert "_No findings._" in md
