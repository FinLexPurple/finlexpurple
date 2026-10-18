"""CLI behavior tests."""

from __future__ import annotations

import re

from typer.testing import CliRunner

from finlexpurple import cli
from finlexpurple.cli import app

runner = CliRunner()
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def strip_ansi(output: str) -> str:
    return _ANSI_ESCAPE.sub("", output)


def test_help_lists_registered_subcommands() -> None:
    result = runner.invoke(app, ["--help"])
    output = strip_ansi(result.stdout)

    assert result.exit_code == 0
    for command in ("setup", "init", "scan", "telemetry", "feedback"):
        assert command in output
    assert "--json-logs" in output


def test_version_prints_current_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert strip_ansi(result.stdout).strip() == "0.0.1"


def test_stubs_exit_successfully_with_phase_message() -> None:
    commands = {
        "scan": "Phase 4",
        "telemetry show": "Phase 14",
        "telemetry on": "Phase 14",
        "telemetry off": "Phase 14",
        "feedback": "Phase 14",
    }
    for command, phase in commands.items():
        result = runner.invoke(app, command.split())
        output = strip_ansi(result.stdout)
        assert result.exit_code == 0, (command, result.exception)
        assert "is not yet implemented" in output
        assert phase in output


def test_setup_runs_phase_two_wizard(monkeypatch) -> None:
    called: list[bool] = []
    monkeypatch.setattr("finlexpurple.cli.run_setup", lambda: called.append(True) or True)

    result = runner.invoke(app, ["setup"])

    assert result.exit_code == 0
    assert called == [True]


def test_json_log_option_is_global_for_subcommands(monkeypatch) -> None:
    seen: list[bool] = []
    monkeypatch.setattr("finlexpurple.cli.configure_logging", lambda json_logs=False: seen.append(json_logs))
    monkeypatch.setattr("finlexpurple.cli.run_setup", lambda: True)

    for command in ("setup", "scan", "telemetry show", "feedback"):
        result = runner.invoke(app, ["--json-logs", *command.split()])
        assert result.exit_code == 0

    assert seen == [True, True, True, True]


def test_init_copies_template_from_package_data_and_does_not_overwrite(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    first = runner.invoke(app, ["init"])
    created = (tmp_path / ".env").read_text(encoding="utf-8")
    (tmp_path / ".env").write_text("preserve-me\n", encoding="utf-8")

    second = runner.invoke(app, ["init"])

    assert first.exit_code == 0, first.stdout
    assert "LLM_PROVIDER=ollama" in created
    assert second.exit_code == 0
    assert "leaving it unchanged" in strip_ansi(second.stdout)
    assert (tmp_path / ".env").read_text(encoding="utf-8") == "preserve-me\n"


def test_init_existing_env_does_not_need_to_read_template(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("preserve-me\n", encoding="utf-8")
    monkeypatch.setattr(cli, "files", lambda _: (_ for _ in ()).throw(AssertionError("read template")))

    result = runner.invoke(app, ["init"])

    assert result.exit_code == 0
    assert "leaving it unchanged" in strip_ansi(result.stdout)
    assert (tmp_path / ".env").read_text(encoding="utf-8") == "preserve-me\n"
