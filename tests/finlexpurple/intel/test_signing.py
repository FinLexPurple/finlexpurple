"""Decision 2: pack verification — identity-pinned, fail-closed, offline hash-only."""

from __future__ import annotations

import hashlib
from pathlib import Path

import pytest

from finlexpurple.intel.signing import (
    GITHUB_ACTIONS_OIDC_ISSUER,
    ExpectedIdentity,
    _cosign_verify_argv,
    verify_pack,
)

_BYTES = b'{"manifest": {}, "patterns": []}'
_HASH = "sha256:" + hashlib.sha256(_BYTES).hexdigest()
_IDENTITY = ExpectedIdentity(identity="https://github.com/FinLexPurple/finlexpurple-intelligence-packs/"
                             ".github/workflows/intel-pack.yml@refs/tags/v1")
_IDENTITY_REGEXP = ExpectedIdentity(
    identity_regexp=r"^https://github\.com/FinLexPurple/finlexpurple-intelligence-packs/"
    r"\.github/workflows/intel-pack\.yml@refs/tags/"
)


class _Backend:
    """Records what it was asked to verify and returns a fixed cosign result."""

    def __init__(self, returncode: int) -> None:
        self._rc = returncode
        self.seen: tuple | None = None

    def __call__(self, identity, issuer, bundle_path, blob_path):
        self.seen = (identity, issuer, bundle_path, blob_path)
        return (self._rc, "", "" if self._rc == 0 else "no matching signatures")


def test_valid_signature_for_pinned_identity_passes() -> None:
    backend = _Backend(0)
    result = verify_pack(
        _BYTES, expected_sha256=_HASH, require_signature=True,
        signature_bundle_path=Path("sig.json"), blob_path=Path("pack.json"),
        expected_identity=_IDENTITY, backend=backend,
    )
    assert result.ok and result.signature_ok is True
    # The pinned identity + the documented GitHub issuer were passed to cosign.
    assert backend.seen[0] == _IDENTITY.identity
    assert backend.seen[1] == GITHUB_ACTIONS_OIDC_ISSUER


def test_wrong_identity_signature_fails_closed() -> None:
    # cosign returns non-zero when the signature is not from the pinned identity.
    result = verify_pack(
        _BYTES, expected_sha256=_HASH, require_signature=True,
        signature_bundle_path=Path("sig.json"), blob_path=Path("pack.json"),
        expected_identity=_IDENTITY, backend=_Backend(1),
    )
    assert result.ok is False and result.signature_ok is False


def test_required_signature_without_pinned_identity_fails_closed() -> None:
    result = verify_pack(_BYTES, expected_sha256=_HASH, require_signature=True, expected_identity=None)
    assert result.ok is False and result.signature_checked is False
    assert any("no pinned identity" in m for m in result.messages)


def test_required_signature_without_bundle_fails_closed() -> None:
    result = verify_pack(
        _BYTES, expected_sha256=_HASH, require_signature=True, expected_identity=_IDENTITY,
    )
    assert result.ok is False and result.signature_checked is False


def test_baseline_hash_only_passes_unsigned() -> None:
    result = verify_pack(_BYTES, expected_sha256=_HASH, require_signature=False)
    assert result.ok is True and result.signature_ok is None
    assert any("hash-only, unsigned" in m for m in result.messages)


def test_hash_mismatch_never_passes() -> None:
    result = verify_pack(b"tampered", expected_sha256=_HASH, require_signature=False)
    assert result.ok is False and result.hash_ok is False


def test_unsigned_without_pinned_hash_is_refused() -> None:
    # Unsigned AND unpinned must be trusted by nothing (fail closed).
    result = verify_pack(_BYTES, expected_sha256=None, require_signature=False)
    assert result.ok is False
    assert any("requires a pinned content hash" in m for m in result.messages)


def test_signed_pack_without_pinned_hash_trusts_the_signature() -> None:
    # On the signed channel the signature covers the exact bytes, so a pinned
    # sha is optional defence-in-depth; absent it, a valid signature stands alone.
    result = verify_pack(
        _BYTES, expected_sha256=None, require_signature=True,
        signature_bundle_path=Path("sig.json"), blob_path=Path("pack.json"),
        expected_identity=_IDENTITY_REGEXP, backend=_Backend(0),
    )
    assert result.ok is True and result.signature_ok is True and result.hash_ok is True


def test_signed_pack_with_mismatched_pinned_hash_still_fails() -> None:
    # A pinned hash that does not match overrides a good signature (defence-in-depth).
    result = verify_pack(
        b"other-bytes", expected_sha256=_HASH, require_signature=True,
        signature_bundle_path=Path("sig.json"), blob_path=Path("pack.json"),
        expected_identity=_IDENTITY, backend=_Backend(0),
    )
    assert result.ok is False and result.hash_ok is False


def test_cosign_argv_uses_exact_identity_flag() -> None:
    argv = _cosign_verify_argv(_IDENTITY, "sig.json", "pack.json")
    assert "--certificate-identity" in argv and "--certificate-identity-regexp" not in argv
    assert _IDENTITY.identity in argv
    assert argv[argv.index("--certificate-oidc-issuer") + 1] == GITHUB_ACTIONS_OIDC_ISSUER


def test_cosign_argv_uses_regexp_identity_flag() -> None:
    argv = _cosign_verify_argv(_IDENTITY_REGEXP, "sig.json", "pack.json")
    assert "--certificate-identity-regexp" in argv
    assert _IDENTITY_REGEXP.identity_regexp in argv


def test_expected_identity_requires_exactly_one_matcher() -> None:
    with pytest.raises(ValueError, match="exactly one"):
        ExpectedIdentity()  # neither
    with pytest.raises(ValueError, match="exactly one"):
        ExpectedIdentity(identity="x", identity_regexp="y")  # both
