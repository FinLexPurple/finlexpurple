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

from finlexpurple.detectors.schema import Finding, FindingStatus, finding_id_slug
from finlexpurple.evidence.bundle import build_bundle_v1, bundle_content_hash, dumps_bundle
from finlexpurple.orchestrator.ulid import ulid_timestamp_ms
from finlexpurple.reporting.aggregate import summarize
from finlexpurple.reporting.badge import badge_for
from finlexpurple.reporting.narrative import Explainer, build_narrative, suggested_fix
from finlexpurple.reporting.writers.cyclonedx_writer import render_cyclonedx
from finlexpurple.reporting.writers.json_writer import report_document
from finlexpurple.reporting.writers.markdown_writer import RenderedFinding, render_markdown
from finlexpurple.reporting.writers.sarif_writer import render_sarif
from finlexpurple.reporting.writers.spdx_writer import render_spdx
from finlexpurple.security.secrets import ensure_owner_only

_SLUG_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


@dataclass(frozen=True)
class ReportPaths:
    """The files and directories a report run produced."""

    directory: Path
    report_json: Path
    report_md: Path
    report_sarif: Path
    report_cyclonedx: Path
    report_spdx: Path
    evidence_dir: Path
    replay_logs_dir: Path


def _slug(target: str) -> str:
    """Filesystem-safe slug for the target portion of the directory name."""

    slug = _SLUG_UNSAFE.sub("-", target.strip()).strip("-")
    return (slug or "target")[:80]


def _started_at(run_id: str, fallback: datetime) -> datetime:
    """An honest run-start time: decode the ULID tail of ``run_id`` if present.

    A run id is ``<slug>-<hash8>-<ULID>``; the ULID encodes the millisecond the
    run directory was created, which is the real start. If ``run_id`` has no
    valid ULID tail (e.g. a test passed a bare name), fall back to ``fallback``
    rather than inventing an earlier time.
    """

    tail = run_id.rsplit("-", 1)[-1]
    try:
        return datetime.fromtimestamp(ulid_timestamp_ms(tail) / 1000, tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return fallback


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
    run_id: str | None = None,
    formats: tuple[str, ...] | None = None,
) -> ReportPaths:
    """Write the full report tree for ``findings`` and return its paths.

    By default the tree is created under ``out_root/<target>-<timestamp>/``. When
    ``out_dir`` is given it is used directly (no ``<target>-<timestamp>`` subdir),
    so a caller such as ``scan`` can place the report inside an existing run
    directory alongside ``run-state.json``. ``run_id`` stamps ``report.json`` and
    gives its ``started_at`` an honest value decoded from the run id's ULID tail;
    when absent the directory name is used and ``started_at`` falls back to the
    generation time.
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
        # The finding id value (flp1:sha256:...) carries colons, illegal in
        # Windows filenames, so on-disk artifacts use a filesystem-safe slug;
        # the id itself is unchanged in report.json.
        slug = finding_id_slug(finding.finding_id)
        evidence_name = f"evidence/{slug}.json"
        _write_owner_only(
            evidence_dir / f"{slug}.json",
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
        replay_name = f"replay-logs/{slug}.log"
        _write_owner_only(replay_logs_dir / f"{slug}.log", finding.verification_log or "")

        bundle_name: str | None = None
        bundle_hash: str | None = None
        if finding.status is FindingStatus.VERIFIED:
            bundle = build_bundle_v1(finding)
            bundle_name = f"evidence/{slug}.bundle.json"
            bundle_hash = bundle_content_hash(bundle)
            _write_owner_only(evidence_dir / f"{slug}.bundle.json", dumps_bundle(bundle))

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
    report_sarif = directory / "report.sarif"
    report_cyclonedx = directory / "report.cyclonedx.json"
    report_spdx = directory / "report.spdx.json"
    resolved_run_id = run_id or directory.name
    started_at = _started_at(resolved_run_id, stamp).isoformat()
    generated_at = stamp.isoformat()
    # --format freeze (Unit 1.4 + 3.1 + 3.2): default writes json+md; a subset writes
    # only those. Every machine format (json/sarif/cyclonedx/spdx) is rendered from the
    # SAME report document, built once here, so the formats can never drift.
    wanted = set(formats) if formats else {"json", "md"}
    document: dict | None = None
    if wanted & {"json", "sarif", "cyclonedx", "spdx"}:
        document = report_document(
            target=target,
            run_id=resolved_run_id,
            started_at=started_at,
            generated_at=generated_at,
            summary=summary,
            findings=findings,
        )
    if "json" in wanted and document is not None:
        _write_owner_only(report_json, json.dumps(document, indent=2, ensure_ascii=True, sort_keys=True) + "\n")
    if "sarif" in wanted and document is not None:
        _write_owner_only(report_sarif, render_sarif(document))
    if "cyclonedx" in wanted and document is not None:
        _write_owner_only(report_cyclonedx, render_cyclonedx(document))
    if "spdx" in wanted and document is not None:
        _write_owner_only(report_spdx, render_spdx(document))
    if "md" in wanted:
        _write_owner_only(
            report_md,
            render_markdown(
                target=target, generated_at=generated_at, summary=summary, rendered=rendered
            ),
        )
    return ReportPaths(
        directory=directory,
        report_json=report_json,
        report_md=report_md,
        report_sarif=report_sarif,
        report_cyclonedx=report_cyclonedx,
        report_spdx=report_spdx,
        evidence_dir=evidence_dir,
        replay_logs_dir=replay_logs_dir,
    )
