"""Decision 2: advisory-only application cannot expand scope, gate, or verify."""

from __future__ import annotations

import json

from finlexpurple.intel.apply import reorder_selection
from finlexpurple.intel.pack import load_pack, record_content_hash


def _pack(fingerprint: str, ordered_agents: list[str], *, provenance: str = "lab"):
    record = {
        "fingerprint": fingerprint, "ordered_agents": ordered_agents,
        "reproduced_strategy": "reorder", "provenance": provenance,
        "content_hash": record_content_hash(
            fingerprint=fingerprint, ordered_agents=ordered_agents,
            reproduced_strategy="reorder", provenance=provenance,
        ),
    }
    return load_pack(json.dumps({
        "manifest": {
            "version": "1", "schema_version": 1, "min_client_version": "0.3.0",
            "created": "2026-11-01T00:00:00Z", "files": [],
            "previous_version": None, "signature_ref": None,
        },
        "patterns": [record],
    }))


def test_reorders_within_the_selected_set() -> None:
    pack = _pack("shop", ["cashier", "hunter"])  # hint flips the order
    assert reorder_selection(["hunter", "cashier"], pack, "shop") == ["cashier", "hunter"]


def test_crafted_pack_cannot_expand_scope() -> None:
    # A malicious pack lists registered specialists the selector did NOT choose.
    pack = _pack("shop", ["teller", "vault", "cashier"])
    result = reorder_selection(["hunter", "cashier"], pack, "shop")
    assert set(result) == {"hunter", "cashier"}   # teller/vault NEVER added
    assert "teller" not in result and "vault" not in result


def test_non_matching_fingerprint_leaves_order_unchanged() -> None:
    pack = _pack("other", ["cashier", "hunter"])
    assert reorder_selection(["hunter", "cashier"], pack, "shop") == ["hunter", "cashier"]


def test_community_record_is_quarantined_by_default() -> None:
    pack = _pack("shop", ["cashier", "hunter"], provenance="community")
    assert reorder_selection(["hunter", "cashier"], pack, "shop") == ["hunter", "cashier"]
    # Only with an explicit opt-in does a community hint reorder (still same set).
    assert reorder_selection(["hunter", "cashier"], pack, "shop", trust_community=True) == ["cashier", "hunter"]


def test_apply_returns_only_names_never_a_gate_or_status() -> None:
    # Structural guarantee: the function yields a list of agent names and nothing
    # that could represent a gate decision or a finding status.
    pack = _pack("shop", ["cashier"])
    result = reorder_selection(["hunter", "cashier"], pack, "shop")
    assert all(isinstance(name, str) for name in result)
