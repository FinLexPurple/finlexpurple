"""Run-state paths and durable, atomic JSON persistence.

Together with ``state.py`` this module satisfies the architecture.md Phase 6
acceptance item that *a run can be killed mid-run and resumed from
run-state.json without repeating completed stages*. It owns two concerns:
deriving a collision-safe per-run directory under ``finlexpurple-reports/``,
and writing/reading the state file atomically so a crash during a write can
never leave a half-written or truncated state behind. On POSIX the file is
written with owner-only (0600) permissions because it records scan metadata.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from finlexpurple.orchestrator.state import InvalidRunStateError, RunState

_WINDOWS_RESERVED = {
    "CON", "PRN", "AUX", "NUL", *(f"COM{i}" for i in range(1, 10)),
    *(f"LPT{i}" for i in range(1, 10)),
}
_RUN_ID = re.compile(r"^[a-z0-9_-]+-[0-9a-f]{8}-[0-9]{8}T[0-9]{6}Z(?:-[0-9]{2})?$")


def create_run_directory(
    target: str,
    *,
    reports_dir: Path | None = None,
    now: datetime | None = None,
) -> tuple[str, Path]:
    """Create a collision-safe target-slug/hash/UTC run directory.

    Returns ``(run_id, directory)``. The run id is
    ``<slug>-<hash8>-<UTCstamp>`` where the slug is a sanitized, length-capped
    form of the target, the hash disambiguates targets that sanitize to the
    same slug, and the UTC timestamp orders runs. ``now`` and ``reports_dir``
    are injectable for deterministic tests. Raises ``ValueError`` on an empty
    target, attempted path traversal, or a generated name that fails the strict
    ``_RUN_ID`` shape, and ``OSError`` if no unique directory is free this
    second.
    """

    canonical = target.strip()
    # Refuse traversal in the raw target before it is ever used in a path.
    if not canonical or ".." in Path(canonical).parts:
        raise ValueError("Target cannot be empty or contain path traversal.")
    # Collapse everything outside [a-z0-9] to single dashes, then length-cap so
    # the final directory name stays well within filesystem limits.
    slug = re.sub(r"[^a-z0-9]+", "-", canonical.lower()).strip("-") or "target"
    slug = slug[:32].rstrip("-_") or "target"
    # A slug that collides with a Windows reserved device name is prefixed so
    # the directory is creatable on Windows as well as POSIX.
    if slug.upper() in _WINDOWS_RESERVED:
        slug = f"target-{slug}"
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:8]
    timestamp = (now or datetime.now(timezone.utc)).astimezone(timezone.utc).strftime(
        "%Y%m%dT%H%M%SZ"
    )
    root = (reports_dir or Path.cwd() / "finlexpurple-reports").resolve()
    root.mkdir(parents=True, exist_ok=True)
    stem = f"{slug}-{digest}-{timestamp}"
    # Two runs of the same target within the same second get a numeric suffix.
    # mkdir (without exist_ok) is the atomic claim that avoids a race here.
    for suffix in range(100):
        run_id = stem if suffix == 0 else f"{stem}-{suffix:02d}"
        if len(run_id) > 80:
            raise ValueError("Generated run directory name exceeds the safe length limit.")
        if not _RUN_ID.fullmatch(run_id):
            raise ValueError("Generated run directory name is not safe.")
        directory = root / run_id
        try:
            directory.mkdir()
        except FileExistsError:
            continue
        return run_id, directory
    raise OSError("Could not allocate a unique run directory for this second.")


def save_state(path: Path, state: RunState) -> None:
    """Atomically replace saved state; use owner-only mode on POSIX.

    Writes to a sibling temp file, flushes and ``fsync``s it, then
    ``os.replace``s it over the target so a reader never observes a partial
    file and a crash cannot corrupt the previous good state. On POSIX the temp
    file and final file are set to 0600. On any ``OSError`` the temp file is
    removed and the error re-raised, leaving any prior state file intact.
    """

    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", dir=path.parent,
            prefix=".run-state-", suffix=".tmp", delete=False,
        ) as stream:
            temporary = Path(stream.name)
            json.dump(state.to_dict(), stream, ensure_ascii=True, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        if os.name != "nt":
            temporary.chmod(0o600)
        os.replace(temporary, path)
        if os.name != "nt":
            path.chmod(0o600)
    except OSError:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
        raise


def load_state(path: Path) -> RunState:
    """Load and validate state without modifying a malformed file.

    Reads and JSON-parses ``path`` and revalidates it through
    ``RunState.from_dict``. Any read, decode, or validation failure raises
    ``InvalidRunStateError`` and the file on disk is left untouched, so a
    corrupt state file can be inspected rather than silently overwritten or
    deleted on a failed resume.
    """

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise InvalidRunStateError("Cannot resume: run-state.json is unreadable or malformed.") from None
    return RunState.from_dict(raw)
