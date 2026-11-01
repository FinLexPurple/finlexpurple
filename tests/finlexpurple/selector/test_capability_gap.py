"""Decision 1: capability-gap detection is report-only and marker-driven."""

from __future__ import annotations

from finlexpurple.selector.capability_gap import CapabilityGap, detect_gaps


def test_detects_known_uncovered_technology() -> None:
    gaps = detect_gaps("POST /graphql HTTP/1.1\nContent-Type: application/json")
    assert [g.technology for g in gaps] == ["graphql"]
    assert gaps[0].vuln_class == "graphql_abuse"


def test_no_gap_for_fully_covered_corpus() -> None:
    assert detect_gaps("GET /checkout?price=1 HTTP/1.1\nServer: nginx") == []


def test_gaps_are_deduplicated_per_technology() -> None:
    # Two distinct websocket markers must still yield a single gap.
    gaps = detect_gaps("ws:// and websocket upgrade and wss://")
    assert [g.technology for g in gaps] == ["websocket"]


def test_to_dict_is_report_shaped() -> None:
    gap = CapabilityGap(technology="saml", vuln_class="saml_authn", reason="r")
    assert gap.to_dict() == {"technology": "saml", "vuln_class": "saml_authn", "reason": "r"}
