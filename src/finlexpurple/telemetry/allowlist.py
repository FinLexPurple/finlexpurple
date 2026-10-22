"""The single source of truth for every field telemetry may ever send (§8).

Nothing leaves the machine unless its key is in :data:`ALLOWED_FIELDS`. The
collector builds payloads only from these keys and the sender refuses to send a
payload containing anything else, so a buggy or malicious caller cannot smuggle
a target URL, request/response data, source code, an API key, or any machine
identifier into a payload. Every field here is deliberately **non-identifying
and product-improvement-only** (§8): coarse environment facts, the opt-in random
install id, aggregate scan counts, and feedback labels — never raw scan data.
"""

from __future__ import annotations

# The complete, fixed allow-list. Adding a field here is the *only* way to make
# it sendable; review every addition against §8 (no target/request/response/
# source/key/identifier may ever appear).
ALLOWED_FIELDS: frozenset[str] = frozenset(
    {
        # What kind of event this payload is (e.g. "install", "scan_summary",
        # "feedback"). Not identifying.
        "event",
        # Coarse environment facts that help triage detection quality. "platform"
        # is the OS family (sys.platform: linux/win32/darwin), never a hostname.
        "app_version",
        "python_version",
        "platform",
        # The opt-in random install id (§22): one locally-generated UUID, the only
        # thing the install counter sends. Not derived from any machine property.
        "install_id",
        # Aggregate scan statistics — counts only, never targets or evidence.
        "total_findings",
        "verified",
        "verified_percent",
        "severity_counts",
        "vulnerability_classes",
        # Feedback labels — the user's rating / mark and the generic finding class
        # (a class name like "sqli", never the finding's URL, payload, or id).
        "run_rating",
        "finding_mark",
        "vulnerability_class",
    }
)


def allowlisted(payload: dict[str, object]) -> dict[str, object]:
    """Return ``payload`` restricted to allow-listed keys (defense in depth)."""

    return {key: value for key, value in payload.items() if key in ALLOWED_FIELDS}


def disallowed_keys(payload: dict[str, object]) -> set[str]:
    """Return any keys in ``payload`` that are not on the allow-list."""

    return {key for key in payload if key not in ALLOWED_FIELDS}
