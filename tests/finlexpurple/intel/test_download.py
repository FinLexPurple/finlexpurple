"""Decision 2: downloader verifies before swapping, blocks egress, refuses rollback."""

from __future__ import annotations

import hashlib
import json

import pytest

from finlexpurple.intel.download import _default_transport, fetch_and_cache
from finlexpurple.intel.pack import record_content_hash
from finlexpurple.intel.signing import ExpectedIdentity
from finlexpurple.security.egress_policy import EgressBlockedError, EgressPolicy

_IDENTITY = ExpectedIdentity(identity="https://github.com/FinLexPurple/finlexpurple-intelligence-packs/"
                             ".github/workflows/publish.yml@refs/tags/v1")
_PACK_URL = "https://packs.example/latest/pack.json"
_SIG_URL = "https://packs.example/latest/pack.sig.json"


def _pack_bytes(created: str) -> bytes:
    rec = {
        "fingerprint": "shop", "ordered_agents": ["hunter", "cashier"],
        "reproduced_strategy": "reorder", "provenance": "lab",
        "content_hash": record_content_hash(
            fingerprint="shop", ordered_agents=["hunter", "cashier"],
            reproduced_strategy="reorder", provenance="lab",
        ),
    }
    return json.dumps({
        "manifest": {
            "version": created, "schema_version": 1, "min_client_version": "0.3.0",
            "created": created, "files": [], "previous_version": None, "signature_ref": "pack.sig.json",
        },
        "patterns": [rec],
    }).encode("utf-8")


def _sha(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _transport(mapping):
    def t(url):
        return mapping[url]
    return t


def _backend(returncode):
    def b(identity, issuer, bundle_path, blob_path):
        return (returncode, "", "" if returncode == 0 else "no matching signatures")
    return b


def test_verified_pack_is_cached(tmp_path) -> None:
    body = _pack_bytes("2026-11-01T00:00:00Z")
    result = fetch_and_cache(
        _PACK_URL, _SIG_URL, egress=EgressPolicy(["packs.example"]), cache_dir=tmp_path / "c",
        expected_sha256=_sha(body), expected_identity=_IDENTITY,
        transport=_transport({_PACK_URL: body, _SIG_URL: b"sigbundle"}), verify_backend=_backend(0),
    )
    assert result.ok and result.cached_pack.exists()
    assert result.version == "2026-11-01T00:00:00Z"


def test_tampered_pack_never_swaps(tmp_path) -> None:
    body = _pack_bytes("2026-11-01T00:00:00Z")
    result = fetch_and_cache(
        _PACK_URL, _SIG_URL, egress=EgressPolicy(["packs.example"]), cache_dir=tmp_path / "c",
        expected_sha256=_sha(b"different"), expected_identity=_IDENTITY,  # wrong expected hash
        transport=_transport({_PACK_URL: body, _SIG_URL: b"sig"}), verify_backend=_backend(0),
    )
    assert result.ok is False
    assert not (tmp_path / "c" / "pack.json").exists()  # good cache (empty) untouched


def test_wrong_identity_signature_never_swaps(tmp_path) -> None:
    body = _pack_bytes("2026-11-01T00:00:00Z")
    result = fetch_and_cache(
        _PACK_URL, _SIG_URL, egress=EgressPolicy(["packs.example"]), cache_dir=tmp_path / "c",
        expected_sha256=_sha(body), expected_identity=_IDENTITY,
        transport=_transport({_PACK_URL: body, _SIG_URL: b"sig"}), verify_backend=_backend(1),
    )
    assert result.ok is False
    assert not (tmp_path / "c" / "pack.json").exists()


def test_rollback_is_refused_then_allowed(tmp_path) -> None:
    cache = tmp_path / "c"
    cache.mkdir()
    (cache / "pack.json").write_bytes(_pack_bytes("2026-11-02T00:00:00Z"))  # newer already installed
    older = _pack_bytes("2026-11-01T00:00:00Z")
    common = {
        "egress": EgressPolicy(["packs.example"]), "cache_dir": cache, "expected_sha256": _sha(older),
        "expected_identity": _IDENTITY, "transport": _transport({_PACK_URL: older, _SIG_URL: b"sig"}),
        "verify_backend": _backend(0),
    }
    refused = fetch_and_cache(_PACK_URL, _SIG_URL, **common)
    assert refused.ok is False and "rollback refused" in refused.reason
    # Cache still holds the newer pack.
    assert b"2026-11-02" in (cache / "pack.json").read_bytes()

    allowed = fetch_and_cache(_PACK_URL, _SIG_URL, allow_rollback=True, **common)
    assert allowed.ok is True
    assert b"2026-11-01" in (cache / "pack.json").read_bytes()


def test_default_transport_blocks_out_of_scope_egress() -> None:
    transport = _default_transport(EgressPolicy(["packs.example"]))
    with pytest.raises(EgressBlockedError):
        transport("https://evil.example/pack.json")  # not allow-listed -> blocked before any socket
