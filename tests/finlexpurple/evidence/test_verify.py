"""Phase 12: offline verification passes clean bundles and catches tampering."""

from __future__ import annotations

import json

from finlexpurple.detectors.schema import Finding, FindingStatus
from finlexpurple.evidence.bundle import build_bundle, dumps_bundle
from finlexpurple.evidence.signing import SigningMode, SigningResult
from finlexpurple.evidence.verify import verify_bundle


def _bundle_text(signing: SigningResult | None = None) -> str:
    finding = Finding.new(
        vulnerability_class="sqli", method="GET", url="http://t.invalid/s", payload="q='"
    )
    finding.status = FindingStatus.VERIFIED
    finding.verification_log = "SQL error reproduced."
    return dumps_bundle(build_bundle(finding, signing=signing))


def test_untampered_bundle_verifies() -> None:
    report = verify_bundle(_bundle_text())
    assert report.ok is True
    assert report.hash_ok is True


def test_tampering_with_payload_is_detected() -> None:
    bundle = json.loads(_bundle_text())
    # Alter the captured evidence but leave the stored hash as-is.
    bundle["payload"]["finding"]["url"] = "http://attacker.invalid/s"
    report = verify_bundle(json.dumps(bundle))
    assert report.ok is False
    assert report.hash_ok is False
    assert any("HASH MISMATCH" in m for m in report.messages)


def test_expected_hash_match_and_mismatch() -> None:
    text = _bundle_text()
    good = verify_bundle(text, expected_hash=json.loads(text)["content_hash"])
    assert good.expected_hash_ok is True and good.ok is True

    bad = verify_bundle(text, expected_hash="sha256:" + "0" * 64)
    assert bad.expected_hash_ok is False and bad.ok is False


def test_signature_present_is_reported_but_not_required_offline() -> None:
    signed = SigningResult(
        requested_mode=SigningMode.SIGSTORE_KEYLESS,
        effective_mode=SigningMode.SIGSTORE_KEYLESS,
        signed=True,
        signature="FAKE-SIG==",
        detail="signed with cosign (sigstore-keyless).",
    )
    report = verify_bundle(_bundle_text(signing=signed))
    assert report.signature_present is True
    assert report.signature_ok is None  # not checked offline
    assert report.ok is True  # the hash guarantee stands on its own
    assert any("not cryptographically verified" in m for m in report.messages)


def test_injected_signature_verifier_can_pass_or_fail() -> None:
    signed = SigningResult(
        requested_mode=SigningMode.SIGSTORE_KEYLESS,
        effective_mode=SigningMode.SIGSTORE_KEYLESS,
        signed=True,
        signature="FAKE-SIG==",
        detail="signed.",
    )
    text = _bundle_text(signing=signed)

    ok = verify_bundle(text, signature_verifier=lambda h, s: (0, "Verified OK", ""))
    assert ok.signature_ok is True and ok.ok is True

    bad = verify_bundle(text, signature_verifier=lambda h, s: (1, "", "signature mismatch"))
    assert bad.signature_ok is False and bad.ok is False
