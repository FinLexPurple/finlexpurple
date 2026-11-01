"""Decision 2: the opt-in contribution diff is categorical-only and never leaks."""

from __future__ import annotations

import pytest

from finlexpurple.detectors.schema import Finding, FindingStatus, Severity
from finlexpurple.intel.contribute import ContributionError, build_contribution


def _finding(vclass: str, url: str, payload: str) -> Finding:
    return Finding.new(vulnerability_class=vclass, method="GET", url=url, payload=payload,
                       severity=Severity.HIGH)


def test_contribution_is_categorical_only_and_omits_sensitive_fields() -> None:
    findings = [_finding("price_tampering", "https://shop.example/checkout?price=0.01", "price=0.01")]
    contribution = build_contribution(findings, technology="stripe")
    record = contribution.records[0]
    assert set(record) == {"technology", "vuln_class", "severity", "status"}
    # No URL, param, or payload leaks into the record or the human-readable diff.
    assert "shop.example" not in contribution.diff_text
    assert "price=0.01" not in contribution.diff_text
    assert record["vuln_class"] == "price_tampering"
    assert record["status"] == FindingStatus.REPORTED.value


def test_records_are_deduplicated() -> None:
    findings = [
        _finding("price_tampering", "https://a.example/c?price=1", "price=1"),
        _finding("price_tampering", "https://b.example/c?price=2", "price=2"),  # same categorical shape
    ]
    contribution = build_contribution(findings, technology="stripe")
    assert len(contribution.records) == 1


def test_community_provenance_is_quarantined_and_labeled() -> None:
    contribution = build_contribution([_finding("xss", "https://x.example/g", "name=x")], technology="nginx")
    assert contribution.provenance == "community" and contribution.quarantined is True
    assert "advisory-only" in contribution.diff_text and "quarantined" in contribution.diff_text


def test_secret_in_a_categorical_field_is_refused() -> None:
    # A secret smuggled via the technology label must trip the scanner and refuse.
    findings = [_finding("xss", "https://x.example/g", "name=x")]
    with pytest.raises(ContributionError, match="secret-like"):
        build_contribution(findings, technology="AKIAIOSFODNN7EXAMPLE")
