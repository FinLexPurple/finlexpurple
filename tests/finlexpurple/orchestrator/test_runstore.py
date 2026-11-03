"""Unit 1.7 (5a): a run saves + resumes identically under JSON and SQLite, the
persisted state carries no query values/bodies, and SQLite WAL lets a reader in
concurrently with a writer."""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from finlexpurple.orchestrator.runstore import (
    JsonRunStore,
    RunStore,
    SqliteRunStore,
    get_run_store,
)
from finlexpurple.orchestrator.state import InvalidRunStateError, RunState


def _state(store: RunStore, *, stage: str = "plan") -> RunState:
    handle = store.create_run("https://shop.example/")
    return RunState(
        run_id=handle.run_id,
        canonical_target="https://shop.example/",
        current_stage=stage,
        catalog=[{"method": "GET", "path": "/search", "parameter_names": ["q", "id"],
                  "content_type": "text/html"}],
        parameter_names=["id", "q"],
    )


def _both_stores(tmp_path: Path) -> list[RunStore]:
    return [
        JsonRunStore(reports_dir=tmp_path / "json"),
        SqliteRunStore(reports_dir=tmp_path / "sqlite"),
    ]


@pytest.mark.parametrize("backend", ["json", "sqlite"])
def test_save_then_resume_round_trips_under_both_backends(backend: str, tmp_path: Path) -> None:
    store = get_run_store(backend, reports_dir=tmp_path / backend)
    state = _state(store)
    store.save_state(state)

    reloaded = store.load_state(state.run_id)
    assert reloaded.to_dict() == state.to_dict()  # identical round-trip

    # A later stage transition persists and resumes just as well.
    state.advance("act")
    store.save_state(state)
    assert store.load_state(state.run_id).current_stage == "act"


def test_json_and_sqlite_persist_identical_state(tmp_path: Path) -> None:
    json_store = JsonRunStore(reports_dir=tmp_path / "j")
    sqlite_store = SqliteRunStore(reports_dir=tmp_path / "s")
    # Same logical run id under each backend, same payload.
    state = _state(json_store)
    json_store.save_state(state)
    sqlite_state = RunState.from_dict(state.to_dict())
    sqlite_store.save_state(sqlite_state)

    assert json_store.load_state(state.run_id).to_dict() == \
        sqlite_store.load_state(sqlite_state.run_id).to_dict()


@pytest.mark.parametrize("backend", ["json", "sqlite"])
def test_list_runs_returns_known_ids_newest_first(backend: str, tmp_path: Path) -> None:
    store = get_run_store(backend, reports_dir=tmp_path / backend)
    first = _state(store)
    store.save_state(first)
    second = _state(store)
    store.save_state(second)
    listed = store.list_runs()
    assert set(listed) == {first.run_id, second.run_id}
    assert listed == sorted(listed, reverse=True)  # ULID tail => newest first


@pytest.mark.parametrize("backend", ["json", "sqlite"])
def test_persisted_state_contains_no_query_values_or_bodies(backend: str, tmp_path: Path) -> None:
    store = get_run_store(backend, reports_dir=tmp_path / backend)
    state = _state(store)
    store.save_state(state)

    # Read the raw persisted bytes for each backend and fuzz for leakage.
    if backend == "json":
        raw = (tmp_path / backend / state.run_id / "run-state.json").read_text(encoding="utf-8")
    else:
        con = sqlite3.connect(tmp_path / backend / "runs.sqlite3")
        raw = con.execute("SELECT state_json FROM runs WHERE run_id=?", (state.run_id,)).fetchone()[0]
        con.close()
    # Only names are present; a query value / body / '?' never is.
    assert '"q"' in raw and '"id"' in raw                 # parameter NAMES are kept
    assert "?" not in raw and "secret" not in raw.lower()  # values never are
    assert "/search" in raw and "sqli" not in raw


def test_both_backends_reject_a_state_carrying_query_values(tmp_path: Path) -> None:
    # The names-only boundary is in RunState.from_dict, so neither backend can be
    # tricked into persisting-then-reloading a catalog path with a query value.
    for store in _both_stores(tmp_path):
        state = _state(store)
        state.catalog[0]["path"] = "/search?q=secret-value"  # smuggle a value in
        store.save_state(state)
        with pytest.raises(InvalidRunStateError):
            store.load_state(state.run_id)


def test_sqlite_is_wal_and_a_reader_is_not_blocked_by_a_writer(tmp_path: Path) -> None:
    store = SqliteRunStore(reports_dir=tmp_path / "s")
    state = _state(store, stage="plan")
    store.save_state(state)
    db = tmp_path / "s" / "runs.sqlite3"

    assert sqlite3.connect(db).execute("PRAGMA journal_mode").fetchone()[0].lower() == "wal"

    writer = sqlite3.connect(db, isolation_level=None)
    writer.execute("PRAGMA journal_mode=WAL")
    writer.execute("BEGIN IMMEDIATE")
    writer.execute("UPDATE runs SET current_stage='verify' WHERE run_id=?", (state.run_id,))

    # A separate reader opens with a short busy timeout: under WAL it reads the
    # last committed snapshot immediately instead of blocking on the open writer.
    reader = sqlite3.connect(db, timeout=1.0)
    stage = reader.execute(
        "SELECT current_stage FROM runs WHERE run_id=?", (state.run_id,)
    ).fetchone()[0]
    assert stage == "plan"  # the committed snapshot, not the writer's uncommitted change

    writer.rollback()
    writer.close()
    reader.close()
