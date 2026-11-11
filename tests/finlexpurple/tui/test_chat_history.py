"""The chat REPL gets a persistent, owner-only input history under the per-user config dir."""

from __future__ import annotations

import os
from pathlib import Path

from prompt_toolkit.history import FileHistory

from finlexpurple.cli import _chat_history


def test_history_is_a_file_history_under_the_config_dir(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    history = _chat_history()
    assert isinstance(history, FileHistory)
    expected = tmp_path / "finlexpurple" / "chat_history"
    assert Path(history.filename) == expected
    assert expected.parent.is_dir()


def test_history_round_trips_across_sessions(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    first = _chat_history()
    first.append_string("scan https://shop.example/")
    # A fresh session reads the same backing file and recalls the earlier line.
    second = _chat_history()
    assert "scan https://shop.example/" in list(second.load_history_strings())


def test_history_directory_is_owner_only(tmp_path: Path, monkeypatch) -> None:
    if os.name == "nt":  # POSIX permission check only
        return
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path))
    _chat_history()
    mode = (tmp_path / "finlexpurple").stat().st_mode & 0o777
    assert mode == 0o700
