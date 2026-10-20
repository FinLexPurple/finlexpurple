"""Phase 12: bundle assembly, canonical hashing, and (de)serialization."""

from __future__ import annotations

import pytest

from finlexpurple.detectors.schema import Finding, FindingStatus
from finlexpurple.evidence.bundle import (
    BundleFormatError,
    build_bundle,
    canonical_json,
    compute_content_hash,
    dumps_bundle,
    load_bundle,
)


def _verified_finding() -> Finding:
    finding = Finding.new(
        vulnerability_class="sqli",
        method="GET",
        url="http://t.invalid/search",
        payload="q='",
        response_snapshot="You have an error in your SQL syntax",
    )
    finding.status = FindingStatus.VERIFIED
    finding.verification_log = "re-executed \"q='\"; SQL error signature reproduced."
    return finding


def test_canonical_json_is_order_independent() -> None:
    assert canonical_json({"b": 1, "a": 2}) == canonical_json({"a": 2, "b": 1})


def test_build_bundle_hash_matches_recomputed_payload_hash() -> None:
    bundle = build_bundle(_verified_finding())
    assert bundle["content_hash"] == compute_content_hash(bundle["payload"])
    assert bundle["content_hash"].startswith("sha256:")


def test_bundle_carries_the_replay_log() -> None:
    bundle = build_bundle(_verified_finding())
    assert "SQL error signature reproduced" in bundle["payload"]["replay_log"]


def test_bundle_defaults_to_hash_only_signing() -> None:
    bundle = build_bundle(_verified_finding())
    assert bundle["signing"]["signed"] is False
    assert bundle["signing"]["effective_mode"] == "hash-only"


def test_roundtrip_dump_and_load() -> None:
    bundle = build_bundle(_verified_finding())
    reloaded = load_bundle(dumps_bundle(bundle))
    assert reloaded == bundle


def test_load_bundle_rejects_non_json() -> None:
    with pytest.raises(BundleFormatError):
        load_bundle("not json {")


def test_load_bundle_rejects_missing_fields() -> None:
    with pytest.raises(BundleFormatError):
        load_bundle('{"payload": {}, "content_hash": "sha256:x"}')  # no 'signing'
