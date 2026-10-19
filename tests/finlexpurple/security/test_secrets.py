"""Phase 7: secrets hygiene (decisions.md §28 item 3)."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from finlexpurple.security.secrets import (
    ensure_owner_only,
    runtime_secret_flags,
    write_secret_file,
)


def test_write_secret_file_is_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "creds" / ".env"
    write_secret_file(path, "ANTHROPIC_API_KEY=xyz\n")
    assert path.read_text(encoding="utf-8") == "ANTHROPIC_API_KEY=xyz\n"
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600


def test_ensure_owner_only(tmp_path: Path) -> None:
    path = tmp_path / "f"
    path.write_text("x", encoding="utf-8")
    if os.name != "nt":
        path.chmod(0o644)
    ensure_owner_only(path)
    if os.name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600


def test_runtime_secret_flags_pass_by_name_not_value() -> None:
    flags = runtime_secret_flags(["ANTHROPIC_API_KEY", "OPENAI_API_KEY"])
    assert flags == ["-e", "ANTHROPIC_API_KEY", "-e", "OPENAI_API_KEY"]
    # No '=value' form — the value is never embedded in a flag.
    assert all("=" not in f for f in flags)


def test_runtime_secret_flags_reject_injection() -> None:
    for bad in ("", "A B", "NAME; rm -rf /", "NAME=value"):
        with pytest.raises(ValueError):
            runtime_secret_flags([bad])
