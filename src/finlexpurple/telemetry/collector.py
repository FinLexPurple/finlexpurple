"""Build telemetry payloads strictly from the allow-list (decisions.md §8).

The four product-analytics events (install, scan_completed, bundle_created,
bundle_verified) are assembled on the frozen envelope
(:mod:`finlexpurple.telemetry.envelope`); the pre-existing ``feedback`` event
(§8) keeps its flat payload. Every builder passes its result through
:func:`allowlist.allowlisted` as a final gate, so a payload's keys are
guaranteed to be a subset of the allow-list by construction — no target,
request/response data, source, key, or machine identifier can be included.
Nothing here sends.
"""

from __future__ import annotations

import platform
import sys
from collections.abc import Mapping
from datetime import datetime
from typing import Any

from finlexpurple import __version__
from finlexpurple.telemetry import allowlist
from finlexpurple.telemetry.envelope import Event, bucket, build_envelope

# The finding statuses whose counts scan_completed may report (bucketed). Kept
# in sync with the allow-listed prop keys so an unknown status is simply dropped.
_STATUS_PROPS = (
    "reported",
    "verified",
    "human_confirmed",
    "inconclusive",
    "not_reproduced",
    "blocked",
)


def build_install_payload(
    install_id: str, *, tool_version: str | None = None, now: datetime | None = None
) -> dict[str, Any]:
    """The install-counter envelope: coarse facts + the random id, no props (§22).

    Carries no event-specific props — a bare install ping. ``event`` and
    ``install_id`` remain top-level so the pre-0.4.0 install counter reads them
    unchanged while ignoring the added envelope fields.
    """

    return allowlist.allowlisted(
        build_envelope(Event.INSTALL, install_id=install_id, tool_version=tool_version, now=now)
    )


def build_scan_completed_payload(
    *,
    install_id: str,
    web: bool,
    mcp: bool,
    deps: bool,
    container: bool,
    status_counts: Mapping[str, int],
    tool_version: str | None = None,
    now: datetime | None = None,
) -> dict[str, Any]:
    """A scan_completed envelope: which surfaces ran + bucketed status counts.

    Surfaces are booleans (never a target); counts are coarse buckets (never the
    raw number of findings). Any status outside the allow-list is dropped.
    """

    props: dict[str, Any] = {
        "web": bool(web),
        "mcp": bool(mcp),
        "deps": bool(deps),
        "container": bool(container),
    }
    for status in _STATUS_PROPS:
        props[status] = bucket(int(status_counts.get(status, 0)))
    return allowlist.allowlisted(
        build_envelope(
            Event.SCAN_COMPLETED,
            install_id=install_id,
            props=props,
            tool_version=tool_version,
            now=now,
        )
    )


def build_bundle_created_payload(
    *, install_id: str, signed: bool, tool_version: str | None = None, now: datetime | None = None
) -> dict[str, Any]:
    """A bundle_created envelope: only whether the bundle was hashed or signed."""

    return allowlist.allowlisted(
        build_envelope(
            Event.BUNDLE_CREATED,
            install_id=install_id,
            props={"bundle_mode": "signed" if signed else "hashed"},
            tool_version=tool_version,
            now=now,
        )
    )


def build_bundle_verified_payload(
    *, install_id: str, passed: bool, tool_version: str | None = None, now: datetime | None = None
) -> dict[str, Any]:
    """A bundle_verified envelope: only whether verification passed or failed."""

    return allowlist.allowlisted(
        build_envelope(
            Event.BUNDLE_VERIFIED,
            install_id=install_id,
            props={"verify_result": "pass" if passed else "fail"},
            tool_version=tool_version,
            now=now,
        )
    )


def build_feedback_payload(
    *,
    run_rating: str | None = None,
    finding_mark: str | None = None,
    vulnerability_class: str | None = None,
) -> dict[str, Any]:
    """A feedback payload (pre-existing §8 event): rating/mark labels + class.

    Kept on its flat pre-0.4.0 shape — deliberately **without** the install id —
    so feedback is never tied to an install. Never includes the run id or
    finding id (both derived from the target); only the user's rating/mark and,
    optionally, the finding's generic vulnerability class.
    """

    payload: dict[str, Any] = {
        "event": Event.FEEDBACK.value,
        "app_version": __version__,
        "python_version": platform.python_version(),
        "platform": sys.platform,  # OS family (linux/win32/darwin), never a hostname
    }
    if run_rating is not None:
        payload["run_rating"] = run_rating
    if finding_mark is not None:
        payload["finding_mark"] = finding_mark
    if vulnerability_class is not None:
        payload["vulnerability_class"] = vulnerability_class
    return allowlist.allowlisted(payload)
