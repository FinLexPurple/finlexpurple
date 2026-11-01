"""Decision 2: the data-only pack model + loader (schema, hashes, registry rule)."""

from __future__ import annotations

import json

import pytest

from finlexpurple.intel.pack import (
    SUPPORTED_SCHEMA_VERSION,
    PackValidationError,
    load_pack,
    record_content_hash,
)


def _record(fingerprint: str, ordered_agents: list[str], *, provenance: str = "lab") -> dict:
    strategy = "reorder"
    return {
        "fingerprint": fingerprint,
        "ordered_agents": ordered_agents,
        "reproduced_strategy": strategy,
        "provenance": provenance,
        "content_hash": record_content_hash(
            fingerprint=fingerprint, ordered_agents=ordered_agents,
            reproduced_strategy=strategy, provenance=provenance,
        ),
    }


def _pack(patterns: list[dict], *, schema_version: int = SUPPORTED_SCHEMA_VERSION) -> str:
    return json.dumps({
        "manifest": {
            "version": "2026.11.01", "schema_version": schema_version,
            "min_client_version": "0.3.0", "created": "2026-11-01T00:00:00Z",
            "files": [], "previous_version": None, "signature_ref": None,
        },
        "patterns": patterns,
    })


def test_valid_pack_loads() -> None:
    pack = load_pack(_pack([_record("payfast-checkout", ["hunter", "cashier"])]))
    assert pack.patterns[0].ordered_agents == ["hunter", "cashier"]
    assert pack.manifest.version == "2026.11.01"


def test_unknown_agent_name_is_rejected() -> None:
    with pytest.raises(PackValidationError, match="not a registered agent"):
        load_pack(_pack([_record("x", ["hunter", "totally_invented"])]))


def test_tampered_record_hash_is_rejected() -> None:
    record = _record("x", ["hunter"])
    record["reproduced_strategy"] = "changed-after-hashing"  # body changed, hash not updated
    with pytest.raises(PackValidationError, match="content_hash mismatch"):
        load_pack(_pack([record]))


def test_unsupported_schema_version_is_rejected() -> None:
    with pytest.raises(PackValidationError, match="unsupported pack schema_version"):
        load_pack(_pack([_record("x", ["hunter"])], schema_version=SUPPORTED_SCHEMA_VERSION + 1))


def test_unknown_provenance_is_rejected() -> None:
    with pytest.raises(PackValidationError, match="unknown provenance"):
        load_pack(_pack([_record("x", ["hunter"], provenance="vendor")]))


def test_extra_key_is_rejected() -> None:
    raw = json.loads(_pack([_record("x", ["hunter"])]))
    raw["patterns"][0]["surprise"] = "smuggled"
    with pytest.raises(PackValidationError):
        load_pack(json.dumps(raw))
