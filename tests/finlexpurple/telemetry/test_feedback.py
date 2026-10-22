"""Phase 17: feedback validates, records locally, and looks up the generic class."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from finlexpurple.telemetry.feedback import FeedbackError, record_feedback


def _run_dir(tmp_path: Path, run_id: str = "run-abc", with_report: bool = False) -> Path:
    root = tmp_path / "finlexpurple-reports"
    d = root / run_id
    d.mkdir(parents=True)
    if with_report:
        (d / "report.json").write_text(
            json.dumps({"findings": [{"finding_id": "F1", "vulnerability_class": "sqli"}]}),
            encoding="utf-8",
        )
    return root


def test_rating_is_recorded_locally(tmp_path: Path) -> None:
    root = _run_dir(tmp_path)
    entry = record_feedback(run_id="run-abc", rating="good", reports_root=root)
    assert entry["rating"] == "good"
    assert (root / "run-abc" / "feedback.jsonl").is_file()


def test_finding_mark_looks_up_class_from_report(tmp_path: Path) -> None:
    root = _run_dir(tmp_path, with_report=True)
    entry = record_feedback(run_id="run-abc", finding_id="F1", mark="false-positive", reports_root=root)
    assert entry["mark"] == "false-positive"
    assert entry["vulnerability_class"] == "sqli"


def test_invalid_rating_and_mark_rejected(tmp_path: Path) -> None:
    root = _run_dir(tmp_path)
    with pytest.raises(FeedbackError):
        record_feedback(run_id="run-abc", rating="amazing", reports_root=root)
    with pytest.raises(FeedbackError):
        record_feedback(run_id="run-abc", finding_id="F1", mark="meh", reports_root=root)


def test_unknown_run_is_rejected(tmp_path: Path) -> None:
    (tmp_path / "finlexpurple-reports").mkdir()
    with pytest.raises(FeedbackError):
        record_feedback(run_id="nope", rating="good", reports_root=tmp_path / "finlexpurple-reports")


def test_requires_rating_or_finding(tmp_path: Path) -> None:
    root = _run_dir(tmp_path)
    with pytest.raises(FeedbackError):
        record_feedback(run_id="run-abc", reports_root=root)


def test_traversal_run_id_rejected(tmp_path: Path) -> None:
    with pytest.raises(FeedbackError):
        record_feedback(run_id="../etc", rating="good", reports_root=tmp_path)
