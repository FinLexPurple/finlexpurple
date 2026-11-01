"""Decision 2: pack verification — identity-pinned, fail-closed, offline hash-only."""

from __future__ import annotations

import hashlib
from pathlib import Path

from finlexpurple.intel.signing import (
    GITHUB_ACTIONS_OIDC_ISSUER,
    ExpectedIdentity,
    verify_pack,
)

_BYTES = b'{"manifest": {}, "patterns": []}'
_HASH = "sha256:" + hashlib.sha256(_BYTES).hexdigest()
_IDENTITY = ExpectedIdentity(identity="https://github.com/FinLexPurple/finlexpurple-intelligence-packs/"
                             ".github/workflows/publish.yml@refs/tags/v1")


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
