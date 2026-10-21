"""Phase 16: on-disk report layout, permissions, and bundle references."""

from __future__ import annotations

import json
import stat
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from finlexpurple.detectors.schema import Finding, FindingStatus
from finlexpurple.reporting.output_layout import write_report

_NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def _verified() -> Finding:
    f = Finding.new(vulnerability_class="sqli", method="GET", url="http://t/s", payload="q='",
                    response_snapshot="error in your SQL syntax")
    f.status = FindingStatus.VERIFIED
    f.verification_log = "re-executed; SQL error reproduced."
    return f


def test_layout_matches_user_guide_section_9(tmp_path: Path) -> None:
    paths = write_report([_verified()], target="https://app.example", out_root=tmp_path, now=_NOW)
    assert paths.directory.name == "https-app.example-20260102T030405Z"
    assert paths.report_json.name == "report.json"
    assert paths.report_md.name == "report.md"
    assert paths.evidence_dir.is_dir() and paths.evidence_dir.name == "evidence"
    assert paths.replay_logs_dir.is_dir() and paths.replay_logs_dir.name == "replay-logs"


def test_verified_finding_gets_bundle_referenced_in_markdown(tmp_path: Path) -> None:
    f = _verified()
    paths = write_report([f], target="t", out_root=tmp_path, now=_NOW)
    bundle = paths.evidence_dir / f"{f.finding_id}.bundle.json"
    assert bundle.is_file()
    md = paths.report_md.read_text()
    assert f"evidence/{f.finding_id}.bundle.json" in md
    # the bundle's content hash is referenced too
    assert json.loads(bundle.read_text())["content_hash"] in md


def test_evidence_and_replay_files_written(tmp_path: Path) -> None:
    f = _verified()
    paths = write_report([f], target="t", out_root=tmp_path, now=_NOW)
    ev = json.loads((paths.evidence_dir / f"{f.finding_id}.json").read_text())
    assert ev["url"] == "http://t/s" and ev["response_snapshot"] == "error in your SQL syntax"
    assert (paths.replay_logs_dir / f"{f.finding_id}.log").read_text() == "re-executed; SQL error reproduced."


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file-mode semantics")
def test_reports_are_owner_only_on_disk(tmp_path: Path) -> None:
    paths = write_report([_verified()], target="t", out_root=tmp_path, now=_NOW)
    assert stat.S_IMODE(paths.report_json.stat().st_mode) == 0o600
    assert stat.S_IMODE(paths.report_md.stat().st_mode) == 0o600
    assert stat.S_IMODE(paths.directory.stat().st_mode) == 0o700


def test_unverified_finding_has_no_bundle(tmp_path: Path) -> None:
    f = Finding.new(vulnerability_class="idor", method="GET", url="http://t/i", payload="id=1")
    paths = write_report([f], target="t", out_root=tmp_path, now=_NOW)
    assert not (paths.evidence_dir / f"{f.finding_id}.bundle.json").exists()


def test_out_dir_writes_report_directly_without_subdir(tmp_path: Path) -> None:
    # scan integration: with out_dir, the report lands in the given directory
    # (no <target>-<timestamp> subdir), e.g. alongside run-state.json.
    run_dir = tmp_path / "an-existing-run"
    run_dir.mkdir()
    paths = write_report([_verified()], target="t", out_dir=run_dir, now=_NOW)
    assert paths.directory == run_dir
    assert (run_dir / "report.json").is_file()
    assert (run_dir / "report.md").is_file()
    assert (run_dir / "evidence").is_dir()
