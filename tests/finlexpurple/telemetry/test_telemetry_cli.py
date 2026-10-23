"""Phase 17: the telemetry/feedback CLI commands, end to end (no real network)."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from finlexpurple.cli import app
from finlexpurple.config import DEFAULT_TELEMETRY_ENDPOINT
from finlexpurple.telemetry import allowlist

runner = CliRunner()


def _isolate(tmp_path: Path, monkeypatch) -> list[tuple[str, dict]]:
    """Isolate config dir + cwd and capture (never send) any telemetry POST."""

    monkeypatch.chdir(tmp_path)
    # Isolate from (and never leak into) the ambient environment: load_dotenv
    # writes .env values into os.environ, which would otherwise bleed between
    # tests. monkeypatch restores these at teardown.
    monkeypatch.delenv("TELEMETRY_ENABLED", raising=False)
    monkeypatch.delenv("TELEMETRY_ENDPOINT", raising=False)
    monkeypatch.setattr(
        "finlexpurple.telemetry.install_counter.user_config_directory",
        lambda: tmp_path / "cfg" / "scopes",
    )
    captured: list[tuple[str, dict]] = []
    monkeypatch.setattr(
        "finlexpurple.telemetry.sender._default_transport",
        lambda url, payload: captured.append((url, payload)) or 200,
    )
    return captured


def test_show_reports_off_by_default_lists_allowlist_and_endpoint(tmp_path, monkeypatch) -> None:
    _isolate(tmp_path, monkeypatch)
    result = runner.invoke(app, ["telemetry", "show"])
    assert result.exit_code == 0, result.output
    assert "Telemetry: OFF (default)" in result.output
    assert DEFAULT_TELEMETRY_ENDPOINT in result.output  # the default endpoint is shown
    for field in allowlist.ALLOWED_FIELDS:
        assert field in result.output  # the user can see every sendable field


def test_on_sends_install_ping_once_then_off_sends_nothing(tmp_path, monkeypatch) -> None:
    captured = _isolate(tmp_path, monkeypatch)

    first = runner.invoke(app, ["telemetry", "on"])
    assert "TELEMETRY_ENABLED=true" in (tmp_path / ".env").read_text()
    assert "Install ping sent" in first.output
    assert len(captured) == 1
    url, payload = captured[0]
    assert url == DEFAULT_TELEMETRY_ENDPOINT
    assert payload["event"] == "install" and set(payload) == {"event", "install_id"}  # minimal

    # A second `on` does not ping again (at most once per install).
    second = runner.invoke(app, ["telemetry", "on"])
    assert "already sent" in second.output
    assert len(captured) == 1

    # Turning off sends nothing.
    runner.invoke(app, ["telemetry", "off"])
    assert "TELEMETRY_ENABLED=false" in (tmp_path / ".env").read_text()
    assert len(captured) == 1


def test_off_by_default_feedback_sends_nothing(tmp_path, monkeypatch) -> None:
    captured = _isolate(tmp_path, monkeypatch)
    run_dir = tmp_path / "finlexpurple-reports" / "run-xyz"
    run_dir.mkdir(parents=True)
    (run_dir / "report.json").write_text(json.dumps({"findings": []}), encoding="utf-8")

    result = runner.invoke(app, ["feedback", "--run", "run-xyz", "--rating", "good"])
    assert result.exit_code == 0, result.output
    assert "Feedback recorded locally" in result.output
    assert "disabled (off by default)" in result.output
    assert captured == []  # nothing left the host while telemetry is off


def test_feedback_bad_rating_exits_nonzero(tmp_path, monkeypatch) -> None:
    _isolate(tmp_path, monkeypatch)
    (tmp_path / "finlexpurple-reports" / "run-xyz").mkdir(parents=True)
    result = runner.invoke(app, ["feedback", "--run", "run-xyz", "--rating", "superb"])
    assert result.exit_code == 2
