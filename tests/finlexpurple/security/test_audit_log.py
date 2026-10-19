"""Phase 7: tamper-evident hash-chained audit log (decisions.md §28 item 5)."""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from finlexpurple.security.audit_log import GENESIS_HASH, AuditLog, AuditLogError


def test_records_chain_and_verifies(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    first = log.record("scope_confirmed", target="https://example.invalid/")
    second = log.record("recon_started")
    assert first["prev_hash"] == GENESIS_HASH
    assert second["prev_hash"] == first["entry_hash"]
    assert log.verify() is True


def test_is_owner_only_on_posix(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    log.record("scope_confirmed")
    if os.name != "nt":
        assert (tmp_path / "audit.jsonl").stat().st_mode & 0o777 == 0o600


def test_tampering_with_an_entry_is_detected(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.record("scope_confirmed", target="a")
    log.record("recon_started")
    lines = path.read_text(encoding="utf-8").splitlines()
    entry = json.loads(lines[0])
    entry["details"]["target"] = "b"  # altered after the fact
    lines[0] = json.dumps(entry, sort_keys=True, separators=(",", ":"))
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    with pytest.raises(AuditLogError, match="tampered"):
        AuditLog.verify_file(path)


def test_dropping_an_entry_breaks_the_chain(tmp_path: Path) -> None:
    path = tmp_path / "audit.jsonl"
    log = AuditLog(path)
    log.record("a")
    log.record("b")
    log.record("c")
    lines = path.read_text(encoding="utf-8").splitlines()
    path.write_text("\n".join([lines[0], lines[2]]) + "\n", encoding="utf-8")  # drop entry 1
    with pytest.raises(AuditLogError):
        AuditLog.verify_file(path)
