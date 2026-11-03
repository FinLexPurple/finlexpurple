"""A SQLite + FTS5 index over knowledge-pack patterns (Unit 1.7).

Knowledge packs (:mod:`finlexpurple.intel.pack`) are data-only: a pattern maps a
target ``fingerprint`` to an ``ordered_agents`` hint plus a free-text
``reproduced_strategy``. As the corpus grows, scanning every record linearly (as
``intel.apply`` does today) does not scale. This module builds the storage path
Phase 2 pack retrieval will use: **exact key first, then full text**, so a lookup
touches only matching rows and never loads the whole corpus into memory.

* ``lookup_fingerprint`` is an indexed exact-key lookup on ``fingerprint``.
* ``search`` is an FTS5 full-text query over ``reproduced_strategy``.

The index is pure storage: it only *reorders known checks*, exactly like the
pack/planner boundary — it never executes a pattern or stores anything a pack did
not already carry. It is built here and unit-tested; wiring it into the live
pack-application path is Phase 2 pack work.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from finlexpurple.intel.pack import Pack, PatternRecord


class PackIndex:
    """A queryable SQLite index over one or more packs' pattern records."""

    def __init__(self, db_path: Path | None = None) -> None:
        # ``:memory:`` by default so a transient index needs no file; callers that
        # want a durable, shareable index pass a path.
        self._connection = sqlite3.connect(str(db_path) if db_path else ":memory:")
        self._connection.row_factory = sqlite3.Row
        self._initialize()

    def _initialize(self) -> None:
        # A regular table for exact-key lookups (fingerprint is indexed) and an
        # external-content FTS5 table over the free-text strategy for full text.
        self._connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS patterns (
                id INTEGER PRIMARY KEY,
                fingerprint TEXT NOT NULL,
                ordered_agents TEXT NOT NULL,
                reproduced_strategy TEXT NOT NULL,
                provenance TEXT NOT NULL,
                content_hash TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_patterns_fingerprint ON patterns(fingerprint);
            CREATE VIRTUAL TABLE IF NOT EXISTS patterns_fts USING fts5(
                reproduced_strategy,
                content='patterns',
                content_rowid='id'
            );
            """
        )

    def add(self, pack: Pack) -> None:
        """Index every pattern in ``pack`` (keeping the FTS table in sync)."""

        with self._connection:
            for record in pack.patterns:
                cursor = self._connection.execute(
                    "INSERT INTO patterns "
                    "(fingerprint, ordered_agents, reproduced_strategy, provenance, content_hash) "
                    "VALUES (?, ?, ?, ?, ?)",
                    (
                        record.fingerprint,
                        json.dumps(record.ordered_agents),
                        record.reproduced_strategy,
                        record.provenance,
                        record.content_hash,
                    ),
                )
                self._connection.execute(
                    "INSERT INTO patterns_fts (rowid, reproduced_strategy) VALUES (?, ?)",
                    (cursor.lastrowid, record.reproduced_strategy),
                )

    @classmethod
    def build(cls, pack: Pack, *, db_path: Path | None = None) -> PackIndex:
        """Build an index from ``pack`` and return it."""

        index = cls(db_path=db_path)
        index.add(pack)
        return index

    def _row_to_record(self, row: sqlite3.Row) -> PatternRecord:
        return PatternRecord(
            fingerprint=row["fingerprint"],
            ordered_agents=json.loads(row["ordered_agents"]),
            reproduced_strategy=row["reproduced_strategy"],
            provenance=row["provenance"],
            content_hash=row["content_hash"],
        )

    def lookup_fingerprint(self, fingerprint: str) -> list[PatternRecord]:
        """Exact-key lookup: every pattern whose fingerprint equals ``fingerprint``."""

        rows = self._connection.execute(
            "SELECT fingerprint, ordered_agents, reproduced_strategy, provenance, content_hash "
            "FROM patterns WHERE fingerprint = ?",
            (fingerprint,),
        ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def search(self, text: str, *, limit: int = 20) -> list[PatternRecord]:
        """Full-text search over ``reproduced_strategy``, best matches first.

        Returns at most ``limit`` records ranked by FTS5 relevance. An empty or
        whitespace-only query returns nothing rather than scanning the corpus.
        """

        if not text.strip():
            return []
        rows = self._connection.execute(
            "SELECT p.fingerprint, p.ordered_agents, p.reproduced_strategy, p.provenance, "
            "       p.content_hash "
            "FROM patterns_fts f JOIN patterns p ON p.id = f.rowid "
            "WHERE patterns_fts MATCH ? ORDER BY rank LIMIT ?",
            (text, limit),
        ).fetchall()
        return [self._row_to_record(row) for row in rows]

    def count(self) -> int:
        """Return how many patterns are indexed."""

        return int(self._connection.execute("SELECT COUNT(*) FROM patterns").fetchone()[0])

    def close(self) -> None:
        """Close the underlying SQLite connection."""

        self._connection.close()
