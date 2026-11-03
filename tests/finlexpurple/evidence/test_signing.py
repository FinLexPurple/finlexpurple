"""Phase 12: signing degrades honestly and never fabricates a signature."""

from __future__ import annotations

from pathlib import Path

from finlexpurple.evidence.signing import (
    SigningMode,
    determine_mode,
    hash_only,
    sign,
    sign_statement,
)

_HASH = "sha256:" + "a" * 64
_PAE = b"DSSEv1 23 application/vnd.in-toto+json 4 {...}"


def test_determine_mode_online_offline_and_managed_key() -> None:
    assert determine_mode(online=True) is SigningMode.SIGSTORE_KEYLESS
    assert determine_mode(online=False) is SigningMode.HASH_ONLY
    assert determine_mode(online=True, managed_key=Path("k.key")) is SigningMode.OFFLINE_MANAGED_KEY
    assert determine_mode(online=False, managed_key=Path("k.key")) is SigningMode.OFFLINE_MANAGED_KEY


def test_hash_only_mode_produces_no_signature() -> None:
    result = sign(_HASH, mode=SigningMode.HASH_ONLY)
    assert result.signed is False
    assert result.signature is None
    assert result.effective_mode is SigningMode.HASH_ONLY


def test_keyless_success_parses_cosigns_real_output() -> None:
    def backend(content_hash: str) -> tuple[int, str, str]:
        assert content_hash == _HASH  # the hash is what gets signed
        return (0, "MEUCIQ-fake-cosign-signature==\n", "")

    result = sign(_HASH, mode=SigningMode.SIGSTORE_KEYLESS, backend=backend)
    assert result.signed is True
    assert result.effective_mode is SigningMode.SIGSTORE_KEYLESS
    assert result.signature == "MEUCIQ-fake-cosign-signature=="  # stdout, verbatim-stripped


def test_signing_failure_degrades_to_honest_hash_only() -> None:
    def failing_backend(content_hash: str) -> tuple[int, str, str]:
        return (1, "", "error: no OIDC token available")

    result = sign(_HASH, mode=SigningMode.SIGSTORE_KEYLESS, backend=failing_backend)
    assert result.signed is False
    assert result.requested_mode is SigningMode.SIGSTORE_KEYLESS
    assert result.effective_mode is SigningMode.HASH_ONLY
    assert "no OIDC token" in result.detail


def test_missing_cosign_degrades_to_honest_hash_only() -> None:
    def missing_backend(content_hash: str) -> tuple[int, str, str]:
        raise FileNotFoundError("cosign not found")

    result = sign(_HASH, mode=SigningMode.SIGSTORE_KEYLESS, backend=missing_backend)
    assert result.signed is False
    assert result.effective_mode is SigningMode.HASH_ONLY
    assert "not installed" in result.detail


def test_empty_signature_is_not_claimed_as_signed() -> None:
    def empty_backend(content_hash: str) -> tuple[int, str, str]:
        return (0, "   \n", "")

    result = sign(_HASH, mode=SigningMode.SIGSTORE_KEYLESS, backend=empty_backend)
    assert result.signed is False
    assert result.effective_mode is SigningMode.HASH_ONLY


def test_hash_only_helper_is_unsigned() -> None:
    result = hash_only()
    assert result.signed is False
    assert result.signature is None


# --- v1: sign_statement signs raw bytes (the DSSE PAE) --------------------


def test_sign_statement_hash_only_produces_no_signature() -> None:
    result = sign_statement(_PAE, mode=SigningMode.HASH_ONLY)
    assert result.signed is False
    assert result.signature is None
    assert result.effective_mode is SigningMode.HASH_ONLY


def test_sign_statement_keyless_success_signs_the_exact_bytes() -> None:
    def backend(message: bytes) -> tuple[int, str, str]:
        assert message == _PAE  # the exact PAE bytes are what gets signed
        return (0, "MEUCIQ-fake-dsse-signature==\n", "")

    result = sign_statement(_PAE, mode=SigningMode.SIGSTORE_KEYLESS, backend=backend)
    assert result.signed is True
    assert result.effective_mode is SigningMode.SIGSTORE_KEYLESS
    assert result.signature == "MEUCIQ-fake-dsse-signature=="
    assert "DSSE PAE" in result.detail


def test_sign_statement_missing_cosign_degrades_to_honest_hash_only() -> None:
    def missing_backend(message: bytes) -> tuple[int, str, str]:
        raise FileNotFoundError("cosign not found")

    result = sign_statement(_PAE, mode=SigningMode.SIGSTORE_KEYLESS, backend=missing_backend)
    assert result.signed is False
    assert result.effective_mode is SigningMode.HASH_ONLY
    assert "not installed" in result.detail


def test_sign_statement_empty_signature_is_not_claimed_as_signed() -> None:
    def empty_backend(message: bytes) -> tuple[int, str, str]:
        return (0, "   \n", "")

    result = sign_statement(_PAE, mode=SigningMode.SIGSTORE_KEYLESS, backend=empty_backend)
    assert result.signed is False
    assert result.effective_mode is SigningMode.HASH_ONLY
