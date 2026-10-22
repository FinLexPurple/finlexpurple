"""Phase 18: the `agents list` and `run --agent` CLI commands."""

from __future__ import annotations

from datetime import datetime, timezone
from types import SimpleNamespace

from typer.testing import CliRunner

from finlexpurple.cli import app

runner = CliRunner()


def test_agents_list_shows_full_roster_and_phase19_slot() -> None:
    result = runner.invoke(app, ["agents", "list"])
    assert result.exit_code == 0, result.output
    for name in ("scout", "marshal", "hunter", "sentinel", "warden", "forge", "herald", "mcp"):
        assert name in result.output
    assert "Phase 19" in result.output  # financial agents' slot


def test_run_sentinel_without_findings_explains_cleanly() -> None:
    result = runner.invoke(app, ["run", "--agent", "sentinel", "--target", "https://example.com/"])
    assert result.exit_code == 2
    assert "findings" in result.output
    assert "Traceback" not in result.output  # a clean message, never a stack trace


def test_run_unknown_agent_is_a_clean_error() -> None:
    result = runner.invoke(app, ["run", "--agent", "bogus", "--target", "https://example.com/"])
    assert result.exit_code == 2
    assert "Unknown agent" in result.output


def test_run_hunter_confirms_scope_attests_and_runs(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    # Avoid the prompt and the network: a cached-style scope + an empty recon.
    monkeypatch.setattr(
        "finlexpurple.cli.confirm_scope",
        lambda target, **kwargs: SimpleNamespace(first_confirmed_at=datetime.now(timezone.utc)),
    )
    monkeypatch.setattr(
        "finlexpurple.cli.run_recon",
        lambda *args, **kwargs: SimpleNamespace(catalog=SimpleNamespace(endpoints=())),
    )
    result = runner.invoke(app, ["run", "--agent", "hunter", "--target", "https://example.com/"])
    assert result.exit_code == 0, result.output
    assert "Authorization attested" in result.output   # safety preserved
    assert "Agent 'hunter'" in result.output
    # an audit log was written for the isolated run
    assert list((tmp_path / "finlexpurple-reports").glob("*/audit.jsonl"))
