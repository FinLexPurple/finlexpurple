"""The chat REPL gets a persistent, owner-only input history under the per-user config dir.

The *location* of that config dir is platform-native and is resolved once, by
``finlexpurple.scope.confirm.user_config_directory`` (``%LOCALAPPDATA%`` on Windows,
``~/Library/Application Support`` on macOS, ``$XDG_CONFIG_HOME`` only on Linux). That
precedence is exercised directly in ``tests/finlexpurple/scope/test_confirm.py``. These
tests cover only what ``_chat_history`` adds on top of it, so — exactly like the telemetry
consumer test — they isolate by monkeypatching ``user_config_directory`` itself rather than
poking a per-OS env var, which would only take effect on Linux and fail on macOS/Windows.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from prompt_toolkit.history import FileHistory

from finlexpurple.cli import _chat_history


def _pin_config_dir(monkeypatch: pytest.MonkeyPatch, root: Path) -> Path:
    # Stand in for the platform-native config dir the same way a real one is shaped
    # (``.../finlexpurple/scopes``); ``_chat_history`` takes its ``.parent`` for the app dir.
    config_dir = root / "finlexpurple" / "scopes"
    monkeypatch.setattr(
        "finlexpurple.scope.confirm.user_config_directory", lambda: config_dir
    )
    return config_dir


def test_history_is_a_file_history_under_the_config_dir(tmp_path: Path, monkeypatch) -> None:
    _pin_config_dir(monkeypatch, tmp_path)
    history = _chat_history()
    assert isinstance(history, FileHistory)
    expected = tmp_path / "finlexpurple" / "chat_history"
    assert Path(history.filename) == expected
    assert expected.parent.is_dir()


def test_history_round_trips_across_sessions(tmp_path: Path, monkeypatch) -> None:
    _pin_config_dir(monkeypatch, tmp_path)
    first = _chat_history()
    first.append_string("scan https://shop.example/")
    # A fresh session reads the same backing file and recalls the earlier line.
    second = _chat_history()
    assert "scan https://shop.example/" in list(second.load_history_strings())


def test_history_directory_is_owner_only(tmp_path: Path, monkeypatch) -> None:
    if os.name == "nt":  # POSIX permission check only
        return
    _pin_config_dir(monkeypatch, tmp_path)
    _chat_history()
    mode = (tmp_path / "finlexpurple").stat().st_mode & 0o777
    assert mode == 0o700
