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
    FINDING_ID_PREFIX,
    FINGERPRINT_PREFIX,
    Finding,
    FindingStatus,
    Severity,
    compute_evidence_hash,
    compute_finding_id,
    compute_fingerprint,
    finding_id_slug,
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


# --- Unit 1.2: versioned ids, normalization, and the host-independent fingerprint


def test_finding_id_is_versioned_and_algorithm_tagged() -> None:
    """The id carries the freeze prefix so a future v2 scheme can coexist."""

    fid = compute_finding_id("GET", "https://x.invalid/a", "p")
    assert fid.startswith(FINDING_ID_PREFIX)
    assert len(fid.removeprefix(FINDING_ID_PREFIX)) == 64  # sha256 hex


def test_finding_id_normalizes_host_case_default_port_and_query_order() -> None:
    """Lowercase host, stripped default port, and sorted query keys are one id."""

    a = compute_finding_id("GET", "https://Example.INVALID:443/a?b=2&a=1", "p")
    b = compute_finding_id("GET", "https://example.invalid/a?a=1&b=2", "p")
    assert a == b


def test_finding_id_route_templates_concrete_ids() -> None:
    """Rotating concrete resource ids collapse to the same route (same finding)."""

    assert compute_finding_id("GET", "https://x.invalid/orders/123", "p") == compute_finding_id(
        "GET", "https://x.invalid/orders/456", "p"
    )


def test_finding_id_keeps_host_distinct() -> None:
    """The finding id is the exact per-target instance: different host, different id."""

    assert compute_finding_id("GET", "https://staging.invalid/a", "p") != compute_finding_id(
        "GET", "https://prod.invalid/a", "p"
    )


def test_fingerprint_matches_across_hosts_but_finding_id_does_not() -> None:
    """Same flaw on staging and prod shares a fingerprint, not a finding_id."""

    staging = Finding.new(vulnerability_class="idor", method="GET",
                          url="https://staging.invalid/orders/1", payload="id=1")
    prod = Finding.new(vulnerability_class="idor", method="GET",
                       url="https://prod.invalid/orders/9", payload="id=9")
    assert staging.fingerprint.startswith(FINGERPRINT_PREFIX)
    assert staging.fingerprint == prod.fingerprint  # host-independent
    assert staging.finding_id != prod.finding_id  # exact per-target instance


def test_fingerprint_distinguishes_vulnerability_class() -> None:
    """A different rule on the same route is a different fingerprint."""

    a = compute_fingerprint("sqli", "https://x.invalid/a", "q=1")
    b = compute_fingerprint("xss", "https://x.invalid/a", "q=1")
    assert a != b


def test_finding_id_slug_is_filesystem_safe() -> None:
    """The on-disk slug drops the colons that are illegal in Windows filenames."""

    slug = finding_id_slug("flp1:sha256:" + "a" * 64)
    assert ":" not in slug and slug == "flp1_sha256_" + "a" * 64


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
