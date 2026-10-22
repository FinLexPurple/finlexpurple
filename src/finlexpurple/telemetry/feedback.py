"""Run and finding feedback (decisions.md §8).

Lets the user rate a run (good / ok / bad) and flag a finding as true- or
false-positive (§8). Feedback is recorded **locally** in the run directory
(owner-only); it references a completed report (Phase 16). What may later be
*sent* as telemetry is built separately by the collector from the allow-list and
excludes the run id and finding id (both derived from the target) — only the
rating/mark label and the generic vulnerability class leave the host, and only
when telemetry is on.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from finlexpurple.security.secrets import ensure_owner_only

RATINGS = frozenset({"good", "ok", "bad"})
MARKS = frozenset({"true-positive", "false-positive"})


class FeedbackError(ValueError):
    """Feedback could not be recorded (bad input or unknown run)."""


def _reports_root(reports_root: Path | None) -> Path:
    return reports_root or (Path.cwd() / "finlexpurple-reports")


def lookup_vulnerability_class(run_dir: Path, finding_id: str) -> str | None:
    """Return the finding's generic class from the run's report.json, if present."""

    try:
        report = json.loads((run_dir / "report.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    for finding in report.get("findings", []):
        if isinstance(finding, dict) and finding.get("finding_id") == finding_id:
            value = finding.get("vulnerability_class")
            return str(value) if value is not None else None
    return None


def record_feedback(
    *,
    run_id: str,
    rating: str | None = None,
    finding_id: str | None = None,
    mark: str | None = None,
    reports_root: Path | None = None,
) -> dict[str, Any]:
    """Validate and record feedback locally; return the recorded entry.

    Requires a rating, or a finding id together with a mark. Raises
    :class:`FeedbackError` on invalid input or an unknown run id.
    """

    if "/" in run_id or "\\" in run_id or ".." in run_id:
        raise FeedbackError("Invalid run id.")
    if rating is None and finding_id is None:
        raise FeedbackError("Provide --rating, or --finding with --mark.")
    if rating is not None and rating not in RATINGS:
        raise FeedbackError(f"rating must be one of: {', '.join(sorted(RATINGS))}.")
    if finding_id is not None and mark is None:
        raise FeedbackError("--finding requires --mark.")
    if mark is not None and mark not in MARKS:
        raise FeedbackError(f"mark must be one of: {', '.join(sorted(MARKS))}.")

    run_dir = _reports_root(reports_root) / run_id
    if not run_dir.is_dir():
        raise FeedbackError(f"No run {run_id!r} found under finlexpurple-reports/.")

    vulnerability_class = lookup_vulnerability_class(run_dir, finding_id) if finding_id else None
    entry: dict[str, Any] = {
        "recorded_at": datetime.now(timezone.utc).isoformat(),
        "run_id": run_id,
        "rating": rating,
        "finding_id": finding_id,
        "mark": mark,
        "vulnerability_class": vulnerability_class,
    }
    log = run_dir / "feedback.jsonl"
    with log.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(entry, sort_keys=True) + "\n")
    ensure_owner_only(log)
    return entry
