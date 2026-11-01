"""Decision 2: the shipped baseline pack loads air-gapped and is hash-pinned."""

from __future__ import annotations

import pytest

from finlexpurple.intel import baseline


def test_baseline_verifies_hash_only_and_loads() -> None:
    result = baseline.verify_baseline()
    assert result.ok is True and result.signature_ok is None   # unsigned, hash-only
    assert any("hash-only, unsigned" in m for m in result.messages)
    pack = baseline.load_baseline()
    assert len(pack.patterns) >= 1
    # Every baseline record only reorders already-registered names (load_pack enforced it).
    assert all(rec.provenance == "lab" for rec in pack.patterns)


def test_corrupted_baseline_fails_the_pinned_hash(monkeypatch) -> None:
    monkeypatch.setattr(baseline, "BASELINE_SHA256", "sha256:" + "0" * 64)
    assert baseline.verify_baseline().ok is False
    with pytest.raises(baseline.BaselineError):
        baseline.load_baseline()
