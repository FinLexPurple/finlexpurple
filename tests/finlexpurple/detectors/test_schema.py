"""Phase 7 acceptance item 1: the universal Finding schema.

Proves the two integrity properties the rest of the system relies on:
``finding_id`` is deterministic for identical method+url+payload, and every
finding is created with status ``reported`` (a detector cannot pre-verify it).
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from finlexpurple.detectors.schema import (
    Finding,
    FindingStatus,
    Severity,
    compute_evidence_hash,
    compute_finding_id,
)


def _make(**overrides):
    params = {
        "vulnerability_class": "sqli",
        "method": "get",
        "url": "https://example.invalid/search",
        "payload": "' OR 1=1--",
        "headers": {"Accept": "text/html"},
        "response_snapshot": "SQL syntax error near ''",
        "expected_signal": "SQL error string in response",
    }
    params.update(overrides)
    return Finding.new(**params)


def test_finding_id_is_deterministic_for_identical_inputs() -> None:
    """Two detections of the same method+url+payload share one finding_id."""

    first = _make(discovered_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
    second = _make(discovered_at=datetime(2026, 6, 1, tzinfo=timezone.utc))
    assert first.finding_id == second.finding_id
    assert first.discovered_at != second.discovered_at


def test_finding_id_changes_when_payload_changes() -> None:
    """A different triggering payload is a different finding."""

    assert _make(payload="a").finding_id != _make(payload="b").finding_id


def test_finding_id_ignores_method_case_and_url_whitespace() -> None:
    """Canonicalization keeps the id stable across trivial formatting."""

    assert compute_finding_id("get", " https://x.invalid/a ", "p") == compute_finding_id(
        "GET", "https://x.invalid/a", "p"
    )


def test_new_finding_is_always_reported() -> None:
    """The factory hard-codes the initial status; it is not a parameter."""

    finding = _make()
    assert finding.status is FindingStatus.REPORTED
    with pytest.raises(TypeError):
        Finding.new(  # type: ignore[call-arg]
            vulnerability_class="xss",
            method="GET",
            url="https://example.invalid/",
            payload="<x>",
            status=FindingStatus.VERIFIED,
        )


def test_evidence_hash_is_stable_across_header_order() -> None:
    """Header insertion order does not change the evidence hash."""

    a = compute_evidence_hash("GET", "u", {"A": "1", "B": "2"}, None, "r")
    b = compute_evidence_hash("GET", "u", {"B": "2", "A": "1"}, None, "r")
    assert a == b


def test_evidence_hash_changes_with_response() -> None:
    """A different response is different evidence."""

    assert _make(response_snapshot="x").evidence_hash != _make(response_snapshot="y").evidence_hash


def test_unknown_fields_are_rejected() -> None:
    """The schema is closed: modules cannot smuggle free-form fields in."""

    data = _make().to_dict()
    data["narrative"] = "the model thinks this is bad"
    with pytest.raises(ValidationError):
        Finding.model_validate(data)


def test_round_trip_preserves_identity_and_enums() -> None:
    """A serialized finding reloads with the same id, status, and severity."""

    original = _make(severity=Severity.HIGH, agent="hunter")
    reloaded = Finding.model_validate(original.to_dict())
    assert reloaded == original
    assert reloaded.to_dict()["status"] == "reported"
    assert reloaded.to_dict()["severity"] == "high"
