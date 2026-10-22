"""Phase 17: the install id is one random local UUID, stable, non-identifying."""

from __future__ import annotations

import uuid
from pathlib import Path

from finlexpurple.telemetry.install_counter import get_or_create_install_id


def test_generates_a_valid_random_uuid(tmp_path: Path) -> None:
    path = tmp_path / "install-id"
    value = get_or_create_install_id(path)
    parsed = uuid.UUID(value)
    assert parsed.version == 4  # random UUIDv4, not derived from host/MAC (uuid1)
    assert path.read_text(encoding="utf-8").strip() == value


def test_is_stable_across_calls(tmp_path: Path) -> None:
    path = tmp_path / "install-id"
    assert get_or_create_install_id(path) == get_or_create_install_id(path)


def test_distinct_installs_get_distinct_ids(tmp_path: Path) -> None:
    a = get_or_create_install_id(tmp_path / "a")
    b = get_or_create_install_id(tmp_path / "b")
    assert a != b


def test_corrupt_file_is_regenerated(tmp_path: Path) -> None:
    path = tmp_path / "install-id"
    path.write_text("not-a-uuid\n", encoding="utf-8")
    value = get_or_create_install_id(path)
    assert uuid.UUID(value)  # replaced with a valid one
