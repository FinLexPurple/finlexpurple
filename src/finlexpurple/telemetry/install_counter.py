"""The privacy-by-architecture install id (decisions.md §22).

On opt-in, the client uses **one random local UUID** as its install identifier.
It is generated with :func:`uuid.uuid4` (random, not derived from any machine
property — no MAC address, hostname, IP, or hardware fingerprint), stored
owner-only in the user config directory, and reused thereafter. The receiving
endpoint counts distinct ids and nothing else; there is no other identifier to
collect. This is the only thing the install counter sends, and only when
telemetry is on.
"""

from __future__ import annotations

import uuid
from pathlib import Path

from finlexpurple.scope.confirm import user_config_directory
from finlexpurple.security.secrets import ensure_owner_only


def install_id_path(directory: Path | None = None) -> Path:
    """Return the local path of the install id file."""

    base = directory or user_config_directory().parent
    return base / "install-id"


def get_or_create_install_id(path: Path | None = None) -> str:
    """Return the stored random install UUID, generating and persisting one once.

    The id is a random UUIDv4. If the stored value is missing or not a valid
    UUID, a fresh one is generated and written owner-only. No machine property
    is ever read or incorporated.
    """

    location = path or install_id_path()
    try:
        existing = location.read_text(encoding="utf-8").strip()
        return str(uuid.UUID(existing))  # validates it is a real UUID
    except (OSError, ValueError):
        pass
    new_id = str(uuid.uuid4())
    location.parent.mkdir(parents=True, exist_ok=True)
    location.write_text(new_id + "\n", encoding="utf-8")
    ensure_owner_only(location)
    return new_id
