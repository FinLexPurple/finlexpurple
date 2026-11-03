"""The single source of truth for every field telemetry may ever send (§8).

Nothing leaves the machine unless its key is on an allow-list here. There are
two allow-lists, because Unit 1.5 froze a nested envelope:

* :data:`ALLOWED_ENVELOPE_FIELDS` — the top-level keys of the versioned event
  envelope (plus the pre-0.4.0 flat feedback payload's keys, kept for
  back-compat so the existing feedback send still passes the gate).
* :data:`ALLOWED_PROP_FIELDS` — the keys allowed inside an envelope's nested
  ``props`` map.

The collector builds payloads only from these keys and the sender refuses to
send a payload containing anything else, so a buggy or malicious caller cannot
smuggle a target URL, request/response data, source code, an API key, or any
machine identifier into a payload. Every field here is deliberately
**non-identifying and product-improvement-only** (§8): coarse environment facts,
the opt-in random install id, bucketed scan counts, and feedback labels — never
raw scan data.
"""

from __future__ import annotations

from typing import Any

# Top-level envelope keys (Unit 1.5). ``props`` is validated separately against
# ALLOWED_PROP_FIELDS. The feedback-only flat keys (run_rating / finding_mark /
# vulnerability_class / app_version / platform) are retained here because the
# pre-existing feedback event keeps its flat payload (§8) rather than moving into
# the envelope — this keeps that send working without changing its privacy shape.
ALLOWED_ENVELOPE_FIELDS: frozenset[str] = frozenset(
    {
        # Versioned envelope (the single wire format for the four product events).
        "schema_version",
        "event",
        "tool_version",
        "python_version",
        "os",
        # The opt-in random install id (§22): one locally-generated UUID, the only
        # thing the install counter sends. Not derived from any machine property.
        "install_id",
        "ts_day",
        "props",
        # Pre-0.4.0 flat feedback payload (kept for back-compat; see module docs).
        "app_version",
        "platform",
        "run_rating",
        "finding_mark",
        "vulnerability_class",
    }
)

# Keys allowed inside an envelope's nested ``props`` map. Adding a key here is the
# *only* way to make it sendable inside props; review every addition against §8.
ALLOWED_PROP_FIELDS: frozenset[str] = frozenset(
    {
        # scan_completed: which scan surfaces ran (booleans, never a target).
        "web",
        "mcp",
        "deps",
        "container",
        # scan_completed: bucketed finding counts by status (bucket strings like
        # "1-9", never a raw count), keyed by FindingStatus value.
        "reported",
        "verified",
        "human_confirmed",
        "inconclusive",
        "not_reproduced",
        "blocked",
        # bundle_created: "hashed" | "signed".
        "bundle_mode",
        # bundle_verified: "pass" | "fail".
        "verify_result",
    }
)

# The complete set of sendable keys (envelope + props), for display and tests.
ALLOWED_FIELDS: frozenset[str] = ALLOWED_ENVELOPE_FIELDS | ALLOWED_PROP_FIELDS


def allowlisted(payload: dict[str, Any]) -> dict[str, Any]:
    """Return ``payload`` restricted to allow-listed keys (defense in depth).

    Top-level keys are filtered against :data:`ALLOWED_ENVELOPE_FIELDS`; a nested
    ``props`` map, if present, is filtered against :data:`ALLOWED_PROP_FIELDS`.
    """

    cleaned: dict[str, Any] = {
        key: value for key, value in payload.items() if key in ALLOWED_ENVELOPE_FIELDS
    }
    props = cleaned.get("props")
    if isinstance(props, dict):
        cleaned["props"] = {
            key: value for key, value in props.items() if key in ALLOWED_PROP_FIELDS
        }
    return cleaned


def disallowed_keys(payload: dict[str, Any]) -> set[str]:
    """Return any keys in ``payload`` that are not allow-listed.

    Bad top-level keys are returned verbatim; bad keys inside ``props`` are
    returned as ``props.<key>`` so the sender's error names them precisely.
    """

    bad = {key for key in payload if key not in ALLOWED_ENVELOPE_FIELDS}
    props = payload.get("props")
    if isinstance(props, dict):
        bad |= {f"props.{key}" for key in props if key not in ALLOWED_PROP_FIELDS}
    return bad
