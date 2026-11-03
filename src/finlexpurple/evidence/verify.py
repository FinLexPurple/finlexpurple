"""Standalone, offline bundle verification (Phase 12; decisions.md §23).

``verify_bundle`` is the heart of the differentiator: given only a bundle file,
it re-derives the canonical content hash and compares it to the stored hash —
**with no network and no scan** — so a third-party auditor can confirm on their
own machine that the bundle was not altered after it was written. If the caller
also supplies the hash the report quoted (``expected_hash``), that end-to-end
chain is checked too. Signature verification is *optional* and injectable (it
wraps ``cosign verify-blob``); it is never required for the offline hash
guarantee, because keyless verification would need connectivity. Any signature
present but not cryptographically checked is reported as exactly that — the hash
result never silently depends on it.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from finlexpurple.evidence.bundle import (
    BUNDLE_FORMAT_V1,
    BundleFormatError,
    compute_content_hash,
    detect_format,
    dsse_pae,
    load_bundle,
)

# Verifies a signature over a content hash; returns cosign's (returncode, stdout, stderr).
SignatureVerifier = Callable[[str, str], tuple[int, str, str]]


@dataclass(frozen=True)
class VerifyReport:
    """The outcome of verifying one bundle. ``ok`` is the overall pass/fail."""

    ok: bool
    hash_ok: bool
    recomputed_hash: str
    stored_hash: str
    expected_hash_ok: bool | None
    signing_mode: str
    signature_present: bool
    signature_ok: bool | None
    messages: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "hash_ok": self.hash_ok,
            "recomputed_hash": self.recomputed_hash,
            "stored_hash": self.stored_hash,
            "expected_hash_ok": self.expected_hash_ok,
            "signing_mode": self.signing_mode,
            "signature_present": self.signature_present,
            "signature_ok": self.signature_ok,
            "messages": list(self.messages),
        }


def verify_bundle(
    text: str,
    *,
    expected_hash: str | None = None,
    signature_verifier: SignatureVerifier | None = None,
) -> VerifyReport:
    """Verify a bundle from its JSON text; offline and standalone by default.

    Recomputes the canonical content hash and compares it to the stored hash
    (the always-offline integrity check). Optionally compares against an
    ``expected_hash`` the auditor got from the report, and optionally verifies a
    present signature via the injected ``signature_verifier``. Raises
    :class:`~finlexpurple.evidence.bundle.BundleFormatError` for a malformed file.
    """

    bundle = load_bundle(text)
    if detect_format(bundle) == BUNDLE_FORMAT_V1:
        return _verify_v1(bundle, expected_hash=expected_hash, signature_verifier=signature_verifier)
    return _verify_v0(bundle, expected_hash=expected_hash, signature_verifier=signature_verifier)


def _verify_v0(
    bundle: dict[str, Any],
    *,
    expected_hash: str | None,
    signature_verifier: SignatureVerifier | None,
) -> VerifyReport:
    """Verify a legacy ``flp-bundle/v0`` bundle by recomputing the canonical payload hash."""

    payload = bundle["payload"]
    stored_hash = bundle["content_hash"]
    signing = bundle["signing"]

    recomputed_hash = compute_content_hash(payload)
    hash_ok = recomputed_hash == stored_hash

    messages: list[str] = []
    if hash_ok:
        messages.append(f"content hash matches ({recomputed_hash}).")
    else:
        messages.append(
            f"HASH MISMATCH: stored {stored_hash}, recomputed {recomputed_hash}. "
            "The bundle was altered after it was created."
        )

    expected_hash_ok: bool | None = None
    if expected_hash is not None:
        expected_hash_ok = _normalize(expected_hash) == _normalize(recomputed_hash)
        if expected_hash_ok:
            messages.append("recomputed hash matches the expected hash supplied by the caller.")
        else:
            messages.append(
                f"EXPECTED-HASH MISMATCH: caller expected {expected_hash}, "
                f"bundle recomputes to {recomputed_hash}."
            )

    signing_mode = str(signing.get("effective_mode", "unknown"))
    signature_present = bool(signing.get("signed")) and bool(signing.get("signature"))
    signature_ok: bool | None = None
    if not signature_present:
        messages.append(
            f"no signature to verify (signing mode: {signing_mode}); "
            "integrity rests on the content hash."
        )
    elif signature_verifier is None:
        messages.append(
            f"signature present (mode: {signing_mode}) but not cryptographically verified "
            "(no verifier supplied / offline); the hash check above stands on its own."
        )
    else:
        returncode, stdout, stderr = signature_verifier(recomputed_hash, str(signing["signature"]))
        signature_ok = returncode == 0
        if signature_ok:
            messages.append(f"signature verified by cosign (mode: {signing_mode}).")
        else:
            detail = stderr.strip() or stdout.strip() or f"cosign exited {returncode}"
            messages.append(f"SIGNATURE VERIFICATION FAILED (mode: {signing_mode}): {detail}.")

    # Overall pass: the hash must match; if an expected hash or a signature check
    # was performed, neither may have failed. An unchecked signature never fails.
    ok = hash_ok and expected_hash_ok is not False and signature_ok is not False
    return VerifyReport(
        ok=ok,
        hash_ok=hash_ok,
        recomputed_hash=recomputed_hash,
        stored_hash=stored_hash,
        expected_hash_ok=expected_hash_ok,
        signing_mode=signing_mode,
        signature_present=signature_present,
        signature_ok=signature_ok,
        messages=messages,
    )


def _verify_v1(
    bundle: dict[str, Any],
    *,
    expected_hash: str | None,
    signature_verifier: SignatureVerifier | None,
) -> VerifyReport:
    """Verify a ``flp-bundle/v1`` bundle by hashing the **exact stored payload bytes**.

    Decodes the base64 DSSE payload and hashes those bytes directly — it never
    re-serializes the document — then compares to the stored ``integrity.digest``.
    A signature, when present, is checked (if a verifier is supplied) over the
    DSSE PAE reconstructed from the same bytes; the offline hash guarantee never
    depends on it.
    """

    dsse = bundle["dsse"]
    integrity = bundle["integrity"]

    try:
        payload_bytes = base64.b64decode(str(dsse["payload"]), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise BundleFormatError(f"v1 bundle 'dsse.payload' is not valid base64: {exc}") from None

    recomputed_digest = hashlib.sha256(payload_bytes).hexdigest()
    stored_digest = str(integrity.get("digest", {}).get("sha256", ""))
    recomputed_hash = f"sha256:{recomputed_digest}"
    stored_hash = f"sha256:{stored_digest}"
    hash_ok = bool(stored_digest) and recomputed_digest == stored_digest

    messages: list[str] = []
    if hash_ok:
        messages.append(f"payload digest matches ({recomputed_hash}); hashed over the exact stored bytes.")
    else:
        messages.append(
            f"HASH MISMATCH: stored {stored_hash}, recomputed {recomputed_hash}. "
            "The bundle payload was altered after it was created."
        )

    expected_hash_ok: bool | None = None
    if expected_hash is not None:
        expected_hash_ok = _normalize(expected_hash) == _normalize(recomputed_hash)
        if expected_hash_ok:
            messages.append("recomputed digest matches the expected hash supplied by the caller.")
        else:
            messages.append(
                f"EXPECTED-HASH MISMATCH: caller expected {expected_hash}, "
                f"bundle recomputes to {recomputed_hash}."
            )

    signing = integrity.get("signing", {})
    signing_mode = str(signing.get("effective_mode") or integrity.get("integrity_level", "unknown"))
    signatures = dsse.get("signatures") or []
    signature = str(signatures[0].get("sig", "")) if signatures else ""
    signature_present = bool(signature)
    signature_ok: bool | None = None
    if not signature_present:
        messages.append(
            f"no signature to verify (signing mode: {signing_mode}); "
            "integrity rests on the payload digest."
        )
    elif signature_verifier is None:
        messages.append(
            f"signature present (mode: {signing_mode}) but not cryptographically verified "
            "(no verifier supplied / offline); the hash check above stands on its own."
        )
    else:
        pae = dsse_pae(str(dsse.get("payloadType", "")), payload_bytes)
        returncode, stdout, stderr = signature_verifier(pae.decode("ascii"), signature)
        signature_ok = returncode == 0
        if signature_ok:
            messages.append(f"signature verified by cosign (mode: {signing_mode}).")
        else:
            detail = stderr.strip() or stdout.strip() or f"cosign exited {returncode}"
            messages.append(f"SIGNATURE VERIFICATION FAILED (mode: {signing_mode}): {detail}.")

    ok = hash_ok and expected_hash_ok is not False and signature_ok is not False
    return VerifyReport(
        ok=ok,
        hash_ok=hash_ok,
        recomputed_hash=recomputed_hash,
        stored_hash=stored_hash,
        expected_hash_ok=expected_hash_ok,
        signing_mode=signing_mode,
        signature_present=signature_present,
        signature_ok=signature_ok,
        messages=messages,
    )


def _normalize(value: str) -> str:
    """Normalize a hash for comparison: drop an optional ``sha256:`` prefix, lowercase."""

    return value.strip().lower().removeprefix("sha256:")
