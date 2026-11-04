"""Two-identity configuration for order-IDOR verification (Unit 2.1).

Order-IDOR is verified by reading one owner-owned resource under **two**
authenticated sessions, so the CLI needs two real identities and the owner's
resource path. These are **operator-supplied**, never guessed: a scan only
attempts order-IDOR verification when ``FLP_IDOR_IDENTITIES`` points at a small
JSON file describing them. Absent (the default), order-IDOR stays a passive
``reported`` candidate — never silently verified.

The file is **data only** — a login path, two usernames, and the owner's order
path. It carries no code and is parsed as JSON, never executed:

    {
      "login_path": "/login",
      "owner": {"user": "alice", "order_path": "/account/orders/ord-alice-0001"},
      "other": {"user": "bob"}
    }
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

ENV_IDOR_IDENTITIES = "FLP_IDOR_IDENTITIES"


class IdorConfigError(ValueError):
    """The order-IDOR identities file is missing a field or is malformed."""


@dataclass(frozen=True)
class IdorIdentity:
    """One identity: the login username and (for the owner) its resource path."""

    user: str
    order_path: str | None = None


@dataclass(frozen=True)
class IdorIdentities:
    """The owner + other identities and the login path, for two-session order-IDOR."""

    login_path: str
    owner: IdorIdentity
    other: IdorIdentity


def _require_str(obj: Mapping[str, object], key: str, where: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str) or not value.strip():
        raise IdorConfigError(f"order-IDOR identities: {where} must be a non-empty string.")
    return value


def parse_identities(data: object) -> IdorIdentities:
    """Validate a parsed identities mapping into an :class:`IdorIdentities`."""

    if not isinstance(data, dict):
        raise IdorConfigError("order-IDOR identities: top level must be a JSON object.")
    owner_raw = data.get("owner")
    other_raw = data.get("other")
    if not isinstance(owner_raw, dict) or not isinstance(other_raw, dict):
        raise IdorConfigError("order-IDOR identities: 'owner' and 'other' must be objects.")
    login_path = _require_str(data, "login_path", "'login_path'")
    owner = IdorIdentity(
        user=_require_str(owner_raw, "user", "owner.user"),
        order_path=_require_str(owner_raw, "order_path", "owner.order_path"),
    )
    other = IdorIdentity(user=_require_str(other_raw, "user", "other.user"))
    return IdorIdentities(login_path=login_path, owner=owner, other=other)


def load_identities(env: Mapping[str, str] | None = None) -> IdorIdentities | None:
    """Load the identities from the ``FLP_IDOR_IDENTITIES`` file, or ``None`` if unset.

    Raises :class:`IdorConfigError` if the var is set but the file is missing,
    unreadable, not JSON, or missing a required field — a misconfiguration fails
    loudly rather than silently skipping verification.
    """

    source = os.environ if env is None else env
    raw_path = source.get(ENV_IDOR_IDENTITIES)
    if raw_path is None or not raw_path.strip():
        return None
    try:
        text = Path(raw_path).read_text(encoding="utf-8")
    except OSError as exc:
        raise IdorConfigError(f"order-IDOR identities: cannot read {raw_path!r}: {exc}.") from None
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise IdorConfigError(f"order-IDOR identities: {raw_path!r} is not valid JSON: {exc}.") from None
    return parse_identities(data)
