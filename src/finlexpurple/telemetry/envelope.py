"""The frozen, versioned telemetry event envelope (Unit 1.5).

Every product-analytics event that may ever be sent shares one envelope so the
wire format is forward-compatible and auditable. The envelope carries only
coarse, non-identifying facts plus a nested, allow-listed ``props`` map for the
event's specifics (:mod:`finlexpurple.telemetry.allowlist` is the gate). It is
**additive over the pre-0.4.0 install ping**: ``event`` and ``install_id`` stay
at the top level, so the existing install counter keeps reading them while new
fields (``schema_version``, ``tool_version``, ``python_version``, ``os``,
``ts_day``, ``props``) are simply extra keys any receiver must ignore when
unknown (forward-compatible ingestion).

Nothing here sends: building an envelope is pure. Telemetry is transmitted only
by an explicit command, only when the user has opted in, and never in the
background (see :mod:`finlexpurple.telemetry.sender`).
"""

from __future__ import annotations

import platform
import sys
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from finlexpurple import __version__

# Bumped only on a breaking change to the envelope's meaning; receivers switch
# on it. Frozen at 1 for 0.4.0.
TELEMETRY_SCHEMA_VERSION = 1


class Event(str, Enum):
    """The closed vocabulary of telemetry events (frozen).

    The four product-analytics events named by the build plan, plus the
    pre-existing opt-in ``feedback`` event (decisions.md §8), which keeps its own
    flat payload for back-compat and is listed here only so the vocabulary is
    complete and typed.
    """

    INSTALL = "install"
    SCAN_COMPLETED = "scan_completed"
    BUNDLE_CREATED = "bundle_created"
    BUNDLE_VERIFIED = "bundle_verified"
    FEEDBACK = "feedback"


def ts_day(now: datetime | None = None) -> str:
    """Return the UTC day as ``YYYY-MM-DD`` — day granularity only, never a time.

    Coarsening to the day on purpose: a precise timestamp would be a weak
    behavioural identifier, so only the calendar day (in UTC) is ever recorded.
    """

    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc).strftime("%Y-%m-%d")


def os_family() -> str:
    """The OS family (``linux`` / ``win32`` / ``darwin``) — never a hostname."""

    return sys.platform


def bucket(count: int) -> str:
    """Coarse-bucket a count so a raw finding total is never transmitted.

    Buckets are deliberately wide (``0`` / ``1-9`` / ``10-49`` / ``50+``): they
    convey rough scale for product analytics without disclosing the exact number
    of findings a particular scan produced.
    """

    if count <= 0:
        return "0"
    if count <= 9:
        return "1-9"
    if count <= 49:
        return "10-49"
    return "50+"


def build_envelope(
    event: Event,
    *,
    install_id: str,
    props: dict[str, Any] | None = None,
    tool_version: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Assemble one telemetry envelope from non-identifying facts.

    ``tool_version`` defaults to the installed package version; ``props`` is the
    event-specific, allow-listed map (empty for a bare install ping). The result
    still has to pass the allow-list gate before it may be sent.
    """

    return {
        "schema_version": TELEMETRY_SCHEMA_VERSION,
        "event": event.value,
        "tool_version": tool_version or __version__,
        "python_version": platform.python_version(),
        "os": os_family(),
        "install_id": install_id,
        "ts_day": ts_day(now),
        "props": dict(props or {}),
    }
