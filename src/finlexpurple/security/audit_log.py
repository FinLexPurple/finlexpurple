"""Tamper-evident, hash-chained audit log (Phase 7; decisions.md §28 item 5).

Every action the agent takes is appended as one entry, and each entry's hash
chains to the previous entry's hash. That makes the log **tamper-evident**: if
any entry is altered, removed, or reordered after the fact, re-verifying the
chain fails at that point. A user can later prove exactly what was and wasn't
tested. (The audit log proves *actions*; the Phase 12 signed evidence bundle
proves *findings*.)

Entries record only non-sensitive metadata — an action name and a small dict of
safe details (never request/response bodies, payloads, or secrets). The file is
written append-only and, on POSIX, owner-only (0600).
"""

from __future__ import annotations

import hashlib
import json
import os
from collections.abc import Mapping
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

GENESIS_HASH = "0" * 64


class AuditLogError(ValueError):
    """The audit log file is malformed or its hash chain does not verify."""


def _entry_hash(seq: int, timestamp: str, action: str, details: Mapping[str, Any], prev_hash: str) -> str:
    """Hash of this entry's content plus the previous entry's hash (the chain link)."""

    canonical = json.dumps(
        {
            "seq": seq,
            "timestamp": timestamp,
            "action": action,
            "details": details,
            "prev_hash": prev_hash,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class AuditLog:
    """An append-only, hash-chained record written to a JSONL file.

    ``record`` appends one entry and returns it; ``verify`` (and the
    ``verify_file`` classmethod) recompute the whole chain and raise
    :class:`AuditLogError` on any break. The genesis entry chains from a fixed
    all-zero hash so an attacker cannot forge a shorter valid prefix.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self._seq = 0
        self._last_hash = GENESIS_HASH
        # Continue an existing chain (e.g. a resumed run appends to the same log)
        # rather than restarting the sequence, which would corrupt it. A broken
        # existing chain raises instead of being appended to.
        if path.exists() and path.stat().st_size > 0:
            self._resume_existing_chain()

    def _resume_existing_chain(self) -> None:
        self.verify_file(self.path)  # raises AuditLogError if the chain is broken
        lines = [line for line in self.path.read_text(encoding="utf-8").splitlines() if line.strip()]
        last = json.loads(lines[-1])
        self._seq = len(lines)
        self._last_hash = last["entry_hash"]

    def record(self, action: str, **details: Any) -> dict[str, Any]:
        """Append one action entry and return it. Details must be non-sensitive."""

        timestamp = datetime.now(timezone.utc).isoformat()
        seq = self._seq
        prev_hash = self._last_hash
        resolved_details = dict(details)
        entry_hash = _entry_hash(seq, timestamp, action, resolved_details, prev_hash)
        entry: dict[str, Any] = {
            "seq": seq,
            "timestamp": timestamp,
            "action": action,
            "details": resolved_details,
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
        }
        line = json.dumps(entry, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(line + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            self.path.chmod(0o600)
        self._seq += 1
        self._last_hash = entry_hash
        return entry

    def verify(self) -> bool:
        """Return ``True`` if the on-disk chain is intact; raise otherwise."""

        return self.verify_file(self.path)

    @classmethod
    def verify_file(cls, path: Path) -> bool:
        """Recompute the whole chain on disk, raising :class:`AuditLogError` on any break."""

        try:
            raw = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise AuditLogError("Audit log is unreadable.") from exc
        prev_hash = GENESIS_HASH
        for index, line in enumerate(l for l in raw.splitlines() if l.strip()):
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise AuditLogError(f"Audit log entry {index} is not valid JSON.") from exc
            if entry.get("seq") != index:
                raise AuditLogError(f"Audit log entry {index} is out of order or missing.")
            if entry.get("prev_hash") != prev_hash:
                raise AuditLogError(f"Audit log entry {index} does not chain to the previous entry.")
            expected = _entry_hash(
                index,
                entry.get("timestamp", ""),
                entry.get("action", ""),
                entry.get("details", {}),
                prev_hash,
            )
            if entry.get("entry_hash") != expected:
                raise AuditLogError(f"Audit log entry {index} has been tampered with.")
            prev_hash = expected
        return True
