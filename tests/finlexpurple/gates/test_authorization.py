"""Phase 8: authorization/scope attestation recording (decisions.md §28 item 7)."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from finlexpurple.gates.authorization import AuthorizationError, record_attestation
from finlexpurple.security.audit_log import AuditLog


def test_attestation_is_recorded_with_target_and_timestamp(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    when = datetime(2026, 10, 20, 9, 30, tzinfo=timezone.utc)
    entry = record_attestation(log, target="https://example.invalid/", attested_at=when)

    assert entry["action"] == "authorization_attested"
    assert entry["details"]["target"] == "https://example.invalid/"
    assert entry["details"]["attested_at"] == when.isoformat()
    # The record is part of the tamper-evident chain.
    assert log.verify() is True


def test_missing_timestamp_is_refused(tmp_path: Path) -> None:
    log = AuditLog(tmp_path / "audit.jsonl")
    with pytest.raises(AuthorizationError, match="no authorization attestation timestamp"):
        record_attestation(log, target="t", attested_at=None)  # type: ignore[arg-type]
