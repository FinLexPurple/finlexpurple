"""Phase 17: the telemetry/feedback CLI commands, end to end."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from finlexpurple.cli import app
from finlexpurple.telemetry import allowlist

runner = CliRunner()


def _isolate(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "finlexpurple.telemetry.install_counter.user_config_directory",
        lambda: tmp_path / "cfg" / "scopes",
    )


def test_show_reports_off_by_default_and_lists_allowlist(tmp_path, monkeypatch) -> None:
    _isolate(tmp_path, monkeypatch)
    result = runner.invoke(app, ["telemetry", "show"])
    assert result.exit_code == 0, result.output
    assert "Telemetry: OFF (default)" in result.output
    assert "not configured" in result.output  # no endpoint hardcoded
    for field in allowlist.ALLOWED_FIELDS:
        assert field in result.output  # the user can see every sendable field


def test_on_then_off_persist_to_env(tmp_path, monkeypatch) -> None:
    _isolate(tmp_path, monkeypatch)
    runner.invoke(app, ["telemetry", "on"])
    assert "TELEMETRY_ENABLED=true" in (tmp_path / ".env").read_text()
    runner.invoke(app, ["telemetry", "off"])
    assert "TELEMETRY_ENABLED=false" in (tmp_path / ".env").read_text()


def test_feedback_records_locally_and_sends_nothing_when_off(tmp_path, monkeypatch) -> None:
    _isolate(tmp_path, monkeypatch)
    run_dir = tmp_path / "finlexpurple-reports" / "run-xyz"
    run_dir.mkdir(parents=True)
    (run_dir / "report.json").write_text(json.dumps({"findings": []}), encoding="utf-8")

    result = runner.invoke(app, ["feedback", "--run", "run-xyz", "--rating", "good"])
    assert result.exit_code == 0, result.output
    assert "Feedback recorded locally" in result.output
    assert "disabled (off by default)" in result.output  # nothing sent
    assert (run_dir / "feedback.jsonl").is_file()


def test_feedback_bad_rating_exits_nonzero(tmp_path, monkeypatch) -> None:
    _isolate(tmp_path, monkeypatch)
    (tmp_path / "finlexpurple-reports" / "run-xyz").mkdir(parents=True)
    result = runner.invoke(app, ["feedback", "--run", "run-xyz", "--rating", "superb"])
    assert result.exit_code == 2
