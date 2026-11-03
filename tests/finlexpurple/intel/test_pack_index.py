"""Unit 1.7: the SQLite+FTS5 pack index — exact key, then full text."""

from __future__ import annotations

from pathlib import Path

from finlexpurple.intel.pack import Manifest, Pack, PatternRecord, record_content_hash
from finlexpurple.intel.pack_index import PackIndex


def _record(fingerprint: str, strategy: str) -> PatternRecord:
    return PatternRecord(
        fingerprint=fingerprint,
        ordered_agents=["hunter"],
        reproduced_strategy=strategy,
        provenance="lab",
        content_hash=record_content_hash(
            fingerprint=fingerprint, ordered_agents=["hunter"],
            reproduced_strategy=strategy, provenance="lab",
        ),
    )


def _pack(*records: PatternRecord) -> Pack:
    manifest = Manifest(version="1", schema_version=1, min_client_version="0", created="2026-01-01")
    return Pack(manifest=manifest, patterns=list(records))


def test_exact_fingerprint_lookup() -> None:
    index = PackIndex.build(_pack(
        _record("fp-order", "order idor cross account read-back"),
        _record("fp-coupon", "coupon stacking persists discount"),
    ))
    hits = index.lookup_fingerprint("fp-order")
    assert [r.reproduced_strategy for r in hits] == ["order idor cross account read-back"]
    assert index.lookup_fingerprint("fp-missing") == []


def test_full_text_search_over_strategy() -> None:
    index = PackIndex.build(_pack(
        _record("fp-order", "order idor cross account read-back"),
        _record("fp-coupon", "coupon stacking persists discount"),
        _record("fp-refund", "duplicate refund exceeds paid amount"),
    ))
    assert [r.fingerprint for r in index.search("coupon")] == ["fp-coupon"]
    assert [r.fingerprint for r in index.search("refund")] == ["fp-refund"]
    # A blank query scans nothing rather than loading the corpus.
    assert index.search("   ") == []


def test_multiple_records_share_a_fingerprint() -> None:
    index = PackIndex.build(_pack(
        _record("fp-order", "two-session cross-account read"),
        _record("fp-order", "sequential-id enumeration"),
    ))
    assert index.count() == 2
    assert len(index.lookup_fingerprint("fp-order")) == 2


def test_index_persists_to_a_file_and_reopens(tmp_path: Path) -> None:
    db = tmp_path / "packs.sqlite3"
    built = PackIndex.build(_pack(_record("fp-order", "order idor cross account")), db_path=db)
    built.close()

    reopened = PackIndex(db_path=db)
    assert reopened.count() == 1
    assert [r.fingerprint for r in reopened.search("idor")] == ["fp-order"]
    reopened.close()
