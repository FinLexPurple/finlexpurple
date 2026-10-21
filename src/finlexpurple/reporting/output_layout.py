"""Assemble the on-disk report layout (Phase 16; §6, §23, §28 #6).

Creates ``./finlexpurple-reports/<target>-<timestamp>/`` with ``report.json``,
``report.md``, an ``evidence/`` directory (raw request/response per finding) and
a ``replay-logs/`` directory (the Phase 11 verification logs), matching
``user-guide.md`` Section 9. For each **verified** finding it also writes the
signed evidence bundle (Phase 12) and the Markdown report references it (§23).

All report files are written **owner-only (0600)** on POSIX and the report
directory **0700** — reports contain real vulnerability detail and must not be
world-readable (§28 #6). On Windows these are no-ops (handled by the shared
``ensure_owner_only`` helper / guarded chmod).
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from finlexpurple.detectors.schema import Finding, FindingStatus
from finlexpurple.evidence.bundle import build_bundle, dumps_bundle
from finlexpurple.reporting.aggregate import summarize
from finlexpurple.reporting.badge import badge_for
from finlexpurple.reporting.narrative import Explainer, build_narrative, suggested_fix
from finlexpurple.reporting.writers.json_writer import render_json
from finlexpurple.reporting.writers.markdown_writer import RenderedFinding, render_markdown
from finlexpurple.security.secrets import ensure_owner_only

_SLUG_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass(frozen=True)
class ReportPaths:
    """The files and directories a report run produced."""

    directory: Path
    report_json: Path
    report_md: Path
    evidence_dir: Path
    replay_logs_dir: Path


def _slug(target: str) -> str:
    """Filesystem-safe slug for the target portion of the directory name."""

    slug = _SLUG_UNSAFE.sub("-", target.strip()).strip("-")
    return (slug or "target")[:80]


def _write_owner_only(path: Path, text: str) -> None:
    path.write_text(text, encoding="utf-8", newline="\n")
    ensure_owner_only(path)


def write_report(
    findings: Sequence[Finding],
    *,
    target: str,
    out_root: Path | None = None,
    out_dir: Path | None = None,
    explainer: Explainer | None = None,
    now: datetime | None = None,
) -> ReportPaths:
    """Write the full report tree for ``findings`` and return its paths.

    By default the tree is created under ``out_root/<target>-<timestamp>/``. When
    ``out_dir`` is given it is used directly (no ``<target>-<timestamp>`` subdir),
    so a caller such as ``scan`` can place the report inside an existing run
    directory alongside ``run-state.json``.
    """

    stamp = now or datetime.now(timezone.utc)
    timestamp = stamp.strftime("%Y%m%dT%H%M%SZ")
    if out_dir is not None:
        directory = out_dir
    else:
        root = out_root or (Path.cwd() / "finlexpurple-reports")
        directory = root / f"{_slug(target)}-{timestamp}"
    evidence_dir = directory / "evidence"
    replay_logs_dir = directory / "replay-logs"
    for d in (directory, evidence_dir, replay_logs_dir):
        d.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            d.chmod(0o700)

    rendered: list[RenderedFinding] = []
    for finding in findings:
        fid = finding.finding_id
        evidence_name = f"evidence/{fid}.json"
        _write_owner_only(
            evidence_dir / f"{fid}.json",
            json.dumps(
                {
                    "method": finding.method,
                    "url": finding.url,
                    "payload": finding.payload,
                    "headers": finding.headers,
                    "body": finding.body,
                    "response_snapshot": finding.response_snapshot,
                    "expected_signal": finding.expected_signal,
                    "evidence_hash": finding.evidence_hash,
                },
                indent=2,
                sort_keys=True,
            ),
        )
        replay_name = f"replay-logs/{fid}.log"
        _write_owner_only(replay_logs_dir / f"{fid}.log", finding.verification_log or "")

        bundle_name: str | None = None
        bundle_hash: str | None = None
        if finding.status is FindingStatus.VERIFIED:
            bundle = build_bundle(finding)
            bundle_name = f"evidence/{fid}.bundle.json"
            bundle_hash = str(bundle["content_hash"])
            _write_owner_only(evidence_dir / f"{fid}.bundle.json", dumps_bundle(bundle))

        rendered.append(
            RenderedFinding(
                finding=finding,
                badge=badge_for(finding.status),
                narrative=build_narrative(finding, explainer=explainer),
                suggested_fix=suggested_fix(finding),
                evidence_file=evidence_name,
                replay_log_file=replay_name,
                bundle_file=bundle_name,
                bundle_hash=bundle_hash,
            )
        )

    summary = summarize(findings)
    report_json = directory / "report.json"
    report_md = directory / "report.md"
    _write_owner_only(
        report_json,
        render_json(target=target, generated_at=stamp.isoformat(), summary=summary, findings=findings),
    )
    _write_owner_only(
        report_md,
        render_markdown(
            target=target, generated_at=stamp.isoformat(), summary=summary, rendered=rendered
        ),
    )
    return ReportPaths(
        directory=directory,
        report_json=report_json,
        report_md=report_md,
        evidence_dir=evidence_dir,
        replay_logs_dir=replay_logs_dir,
    )
