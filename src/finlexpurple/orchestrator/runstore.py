"""The RunStore interface and its JSON and SQLite backends (Unit 1.7).

The orchestrator depends on the :class:`RunStore` *interface* — not on
``json.dump`` or a concrete path — so a run can be persisted by either backend
with identical behaviour:

* :class:`JsonRunStore` wraps today's behaviour exactly: one atomic, owner-only
  ``<run_id>/run-state.json`` per run (via :mod:`finlexpurple.orchestrator.persistence`).
* :class:`SqliteRunStore` stores the same state as a row in a WAL-mode SQLite
  database, so concurrent readers never block the writer.

Both backends create the same per-run directory for a run's *artifacts*
(``report.json`` / evidence / bundles stay plain files regardless of backend),
and both persist only what :class:`~finlexpurple.orchestrator.state.RunState`
allows — endpoint paths and parameter **names**, never query values or bodies.
That **names-only privacy boundary** is part of this interface's contract:
``save_state`` serializes ``RunState.to_dict()`` and ``load_state`` revalidates
through ``RunState.from_dict``, so neither backend can widen what is stored.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Protocol, runtime_checkable

from finlexpurple.orchestrator.persistence import (
    create_run_directory,
)
from finlexpurple.orchestrator.persistence import (
    load_state as _json_load_state,
)
from finlexpurple.orchestrator.persistence import (
    save_state as _json_save_state,
)
from finlexpurple.orchestrator.state import InvalidRunStateError, RunState

DEFAULT_RUN_STORE = "json"
_RUN_STATE_FILENAME = "run-state.json"
_SQLITE_FILENAME = "runs.sqlite3"


def _default_reports_dir() -> Path:
    return Path.cwd() / "finlexpurple-reports"


@dataclass(frozen=True)
class RunHandle:
    """A created run: its id and the directory its artifacts are written to."""

    run_id: str
    directory: Path


@runtime_checkable
class RunStore(Protocol):
    """The persistence interface the orchestrator depends on.

    Implementations must preserve the names-only boundary: they persist exactly
    ``RunState.to_dict()`` and reload through ``RunState.from_dict`` (which
    rejects query values/bodies), so no backend can store more than the state
    model permits.
    """

    def create_run(self, target: str, *, now: datetime | None = None) -> RunHandle:
        """Reserve a collision-safe run id + artifact directory for ``target``."""

    def save_state(self, state: RunState) -> None:
        """Durably persist ``state`` (keyed by ``state.run_id``)."""

    def load_state(self, run_id: str) -> RunState:
        """Load and revalidate the state for ``run_id`` (raises if missing/malformed)."""

    def list_runs(self) -> list[str]:
        """Return known run ids, newest first (ids sort by their ULID tail)."""

    def run_directory(self, run_id: str) -> Path:
        """Return the artifact directory for ``run_id``."""


class JsonRunStore:
    """RunStore backed by one atomic ``<run_id>/run-state.json`` per run (default)."""

    def __init__(self, reports_dir: Path | None = None) -> None:
        self._reports_dir = (reports_dir or _default_reports_dir())

    def _state_path(self, run_id: str) -> Path:
        return self._reports_dir / run_id / _RUN_STATE_FILENAME

    def create_run(self, target: str, *, now: datetime | None = None) -> RunHandle:
        run_id, directory = create_run_directory(target, reports_dir=self._reports_dir, now=now)
        return RunHandle(run_id=run_id, directory=directory)

    def save_state(self, state: RunState) -> None:
        _json_save_state(self._state_path(state.run_id), state)

    def load_state(self, run_id: str) -> RunState:
        return _json_load_state(self._state_path(run_id))

    def list_runs(self) -> list[str]:
        if not self._reports_dir.is_dir():
            return []
        runs = [
            child.name
            for child in self._reports_dir.iterdir()
            if child.is_dir() and (child / _RUN_STATE_FILENAME).is_file()
        ]
        return sorted(runs, reverse=True)

    def run_directory(self, run_id: str) -> Path:
        return self._reports_dir / run_id


class SqliteRunStore:
    """RunStore backed by a WAL-mode SQLite database (same names-only state).

    The run's artifact directory is still created on disk (so report/evidence
    files are written exactly as under the JSON backend); only the run-state
    itself moves into the database. WAL journaling lets a reader open the DB
    concurrently with the writer without blocking.
    """

    def __init__(self, reports_dir: Path | None = None, *, db_path: Path | None = None) -> None:
        self._reports_dir = (reports_dir or _default_reports_dir())
        self._db_path = db_path or (self._reports_dir / _SQLITE_FILENAME)
        self._reports_dir.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._db_path, isolation_level=None)
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA foreign_keys=ON")
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS runs ("
                "  run_id TEXT PRIMARY KEY,"
                "  canonical_target TEXT NOT NULL,"
                "  current_stage TEXT NOT NULL,"
                "  updated_at TEXT NOT NULL,"
                "  state_json TEXT NOT NULL"
                ")"
            )

    def create_run(self, target: str, *, now: datetime | None = None) -> RunHandle:
        run_id, directory = create_run_directory(target, reports_dir=self._reports_dir, now=now)
        return RunHandle(run_id=run_id, directory=directory)

    def save_state(self, state: RunState) -> None:
        # Exactly the canonical JSON the file backend writes; the names-only
        # boundary is guaranteed by RunState, not by this backend.
        state_json = json.dumps(state.to_dict(), ensure_ascii=True, sort_keys=True)
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO runs (run_id, canonical_target, current_stage, updated_at, state_json) "
                "VALUES (?, ?, ?, ?, ?) "
                "ON CONFLICT(run_id) DO UPDATE SET "
                "  canonical_target=excluded.canonical_target,"
                "  current_stage=excluded.current_stage,"
                "  updated_at=excluded.updated_at,"
                "  state_json=excluded.state_json",
                (
                    state.run_id,
                    state.canonical_target,
                    state.current_stage,
                    datetime.now().astimezone().isoformat(),
                    state_json,
                ),
            )

    def load_state(self, run_id: str) -> RunState:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT state_json FROM runs WHERE run_id = ?", (run_id,)
            ).fetchone()
        if row is None:
            raise InvalidRunStateError(f"Cannot resume: no run {run_id!r} in the run store.")
        try:
            raw = json.loads(row[0])
        except json.JSONDecodeError:
            raise InvalidRunStateError("Cannot resume: stored run state is malformed.") from None
        return RunState.from_dict(raw)

    def list_runs(self) -> list[str]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT run_id FROM runs ORDER BY run_id DESC"
            ).fetchall()
        return [row[0] for row in rows]

    def run_directory(self, run_id: str) -> Path:
        return self._reports_dir / run_id


def get_run_store(name: str | None = None, *, reports_dir: Path | None = None) -> RunStore:
    """Build the selected RunStore backend; defaults to JSON.

    ``name`` is normally the ``FLP_RUN_STORE`` value (``json`` / ``sqlite``); an
    unknown value raises :class:`ValueError`, so a typo fails loudly rather than
    silently falling back.
    """

    selected = (name or DEFAULT_RUN_STORE).strip().lower()
    if selected == "json":
        return JsonRunStore(reports_dir=reports_dir)
    if selected == "sqlite":
        return SqliteRunStore(reports_dir=reports_dir)
    raise ValueError(f"unknown run store {selected!r}; expected 'json' or 'sqlite'.")
