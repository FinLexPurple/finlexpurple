"""Build telemetry payloads strictly from the allow-list (decisions.md §8).

Every payload is assembled from known, non-identifying fields and then passed
through :func:`allowlist.allowlisted` as a final gate, so a payload's keys are
guaranteed to be a subset of the allow-list by construction — no target, request/
response data, source, key, or machine identifier can be included.
"""

from __future__ import annotations

import platform
import sys
from typing import Any

from finlexpurple import __version__
from finlexpurple.telemetry import allowlist


def _environment() -> dict[str, Any]:
    """Coarse, non-identifying environment facts (OS family, versions)."""

    return {
        "app_version": __version__,
        "python_version": platform.python_version(),
        "platform": sys.platform,  # OS family (linux/win32/darwin), never a hostname
    }


def build_install_payload(install_id: str) -> dict[str, Any]:
    """The install-counter payload: the single random id and nothing else (§22).

    Deliberately carries no other field — not even coarse environment — so it is
    a single random local UUID with no other identifier of any kind.
    """

    return allowlist.allowlisted({"event": "install", "install_id": install_id})


def build_scan_summary_payload(
    *,
    total_findings: int,
    verified: int,
    verified_percent: float,
    severity_counts: dict[str, int],
    vulnerability_classes: list[str],
) -> dict[str, Any]:
    """Aggregate scan statistics — counts and class names only, never evidence."""

    return allowlist.allowlisted(
        {
            "event": "scan_summary",
            "total_findings": total_findings,
            "verified": verified,
            "verified_percent": verified_percent,
            "severity_counts": dict(severity_counts),
            "vulnerability_classes": sorted(set(vulnerability_classes)),
            **_environment(),
        }
    )


def build_feedback_payload(
    *,
    run_rating: str | None = None,
    finding_mark: str | None = None,
    vulnerability_class: str | None = None,
) -> dict[str, Any]:
    """A feedback payload: the rating/mark labels and the generic finding class.

    Never includes the run id or finding id (both derived from the target); only
    the user's rating/mark and, optionally, the finding's vulnerability class.
    """

    payload: dict[str, Any] = {"event": "feedback", **_environment()}
    if run_rating is not None:
        payload["run_rating"] = run_rating
    if finding_mark is not None:
        payload["finding_mark"] = finding_mark
    if vulnerability_class is not None:
        payload["vulnerability_class"] = vulnerability_class
    return allowlist.allowlisted(payload)
