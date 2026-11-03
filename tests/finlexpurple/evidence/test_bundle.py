"""Phase 12: bundle assembly, canonical hashing, and (de)serialization."""

from __future__ import annotations

import base64
import hashlib
import json

import pytest

from finlexpurple.detectors.schema import Finding, FindingStatus
from finlexpurple.evidence.bundle import (
    BUNDLE_FORMAT_V1,
    BUNDLE_TYPE_URI,
    DSSE_PAYLOAD_TYPE,
    IN_TOTO_STATEMENT_TYPE,
    BundleFormatError,
    build_bundle,
    build_bundle_v1,
    bundle_content_hash,
    canonical_json,
    compute_content_hash,
    detect_format,
    dsse_pae,
    dumps_bundle,
    load_bundle,
)
from finlexpurple.evidence.signing import SigningMode, SigningResult


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


# --- v1: DSSE + in-toto Statement -----------------------------------------


def test_dsse_pae_matches_spec() -> None:
    # "DSSEv1 <len(type)> <type> <len(body)> <body>", lengths as ASCII decimal.
    assert dsse_pae("ty", b"hello") == b"DSSEv1 2 ty 5 hello"


def test_v1_bundle_shape_and_in_toto_statement() -> None:
    finding = _verified_finding()
    bundle = build_bundle_v1(finding)
    assert bundle["bundle_format"] == BUNDLE_FORMAT_V1
    assert detect_format(bundle) == BUNDLE_FORMAT_V1
    assert bundle["dsse"]["payloadType"] == DSSE_PAYLOAD_TYPE

    statement = json.loads(base64.b64decode(bundle["dsse"]["payload"]))
    assert statement["_type"] == IN_TOTO_STATEMENT_TYPE
    assert statement["predicateType"] == BUNDLE_TYPE_URI
    # subject binds the finding's request/response evidence_hash (bare hex).
    assert statement["subject"][0]["name"] == finding.finding_id
    assert statement["subject"][0]["digest"]["sha256"] == finding.evidence_hash
    # amounts/ids ride inside the finding as strings (algorithm-agile digest map).
    assert set(bundle["integrity"]["digest"]) == {"sha256"}


def test_v1_digest_is_over_the_exact_stored_bytes() -> None:
    bundle = build_bundle_v1(_verified_finding())
    payload_bytes = base64.b64decode(bundle["dsse"]["payload"])
    assert bundle["integrity"]["digest"]["sha256"] == hashlib.sha256(payload_bytes).hexdigest()
    assert bundle_content_hash(bundle) == f"sha256:{hashlib.sha256(payload_bytes).hexdigest()}"


def test_v1_defaults_to_hashed_integrity_level() -> None:
    bundle = build_bundle_v1(_verified_finding())
    assert bundle["integrity"]["integrity_level"] == "hashed"
    assert bundle["integrity"]["signer_identity"] is None
    assert bundle["dsse"]["signatures"][0]["sig"] == ""


def test_v1_signed_sets_signed_level_and_carries_signature() -> None:
    signed = SigningResult(
        requested_mode=SigningMode.SIGSTORE_KEYLESS,
        effective_mode=SigningMode.SIGSTORE_KEYLESS,
        signed=True,
        signature="FAKE-DSSE-SIG==",
        detail="signed with cosign (sigstore-keyless).",
    )
    bundle = build_bundle_v1(_verified_finding(), signing=signed)
    assert bundle["integrity"]["integrity_level"] == "signed"
    assert bundle["integrity"]["signer_identity"] == signed.detail
    assert bundle["dsse"]["signatures"][0]["sig"] == "FAKE-DSSE-SIG=="


def test_v1_roundtrip_dump_and_load() -> None:
    bundle = build_bundle_v1(_verified_finding())
    assert load_bundle(dumps_bundle(bundle)) == bundle


def test_load_bundle_rejects_malformed_v1() -> None:
    with pytest.raises(BundleFormatError):
        # declared v1 but missing the DSSE payload field
        load_bundle('{"bundle_format": "flp-bundle/v1", "dsse": {}, "integrity": {"digest": {}}}')
