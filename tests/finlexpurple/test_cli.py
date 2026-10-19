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


def test_non_scan_stubs_exit_successfully_with_phase_message() -> None:
    commands = {
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
    monkeypatch.setattr(
        "finlexpurple.cli.run_setup",
        lambda fake_hardware_profile=None: called.append(True) or True,
    )

    result = runner.invoke(app, ["setup"])

    assert result.exit_code == 0
    assert called == [True]


def test_doctor_prints_facts_without_full_paths_or_secrets(monkeypatch, tmp_path) -> None:
    from finlexpurple.hardware.detect import HardwareFacts

    facts = HardwareFacts(
        total_ram_gb=16,
        model_directory=tmp_path / "private-home" / ".ollama" / "models",
        disk_checked_path=tmp_path / "private-home",
        free_disk_gb=12,
        gpu_kind="none",
        gpu_name=None,
        gpu_memory_gb=None,
        operating_system="Synthetic OS",
    )
    monkeypatch.setattr(cli, "detect_hardware", lambda: facts)

    result = runner.invoke(app, ["doctor"])
    output = strip_ansi(result.output)

    assert result.exit_code == 0
    assert "Total system RAM: 16.0 GB" in output
    assert "Free disk space: 12.0 GB" in output
    assert "private-home" not in output
    assert "API_KEY" not in output


def test_doctor_fake_hardware_profile_is_explicit_and_sanitized() -> None:
    result = runner.invoke(app, ["doctor", "--fake-hardware-profile", "apple-24gb"])
    output = strip_ansi(result.output)

    assert result.exit_code == 0
    assert "Hardware source: synthetic profile apple-24gb" in output
    assert "GPU: apple_silicon" in output
    assert "Total system RAM: 24.0 GB" in output
    assert "<synthetic" not in output


def test_setup_rejects_unknown_fake_hardware_profile() -> None:
    result = runner.invoke(app, ["setup", "--fake-hardware-profile", "made-up"])

    assert result.exit_code == 2
    assert "Unknown hardware profile" in strip_ansi(result.output)


def test_json_log_option_is_global_for_subcommands(monkeypatch) -> None:
    seen: list[bool] = []
    monkeypatch.setattr("finlexpurple.cli.configure_logging", lambda json_logs=False: seen.append(json_logs))
    monkeypatch.setattr("finlexpurple.cli.run_setup", lambda fake_hardware_profile=None: True)
    monkeypatch.setattr("finlexpurple.cli.confirm_scope", lambda target: object())

    commands = (
        ["setup"],
        ["scan", "--target", "https://example.com/"],
        ["telemetry", "show"],
        ["feedback"],
    )
    for command in commands:
        result = runner.invoke(app, ["--json-logs", *command])
        assert result.exit_code == 0

    assert seen == [True, True, True, True]


def test_scan_requires_target_option() -> None:
    result = runner.invoke(app, ["scan"])

    assert result.exit_code == 2
    assert "--target" in strip_ansi(result.output)


def test_scan_confirms_scope_then_reports_stub_behavior(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        "finlexpurple.scope.confirm.user_config_directory", lambda: tmp_path / "user-config"
    )
    result = runner.invoke(app, ["scan", "--target", "https://example.com/app"], input="y\n")

    output = strip_ansi(result.output)
    assert result.exit_code == 0, output
    assert "Resolved target: https://example.com/app" in output
    assert "Subdomains intended for enumeration: none" in output
    assert "path /app and its descendants" in output
    assert "exact host example.com" in output
    assert "Scope confirmed. Scanning is not implemented yet." in output
    assert len(list((tmp_path / "user-config").glob("*.json"))) == 1


def test_scan_uses_cached_confirmation_without_prompting_again(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        "finlexpurple.scope.confirm.user_config_directory", lambda: tmp_path / "user-config"
    )
    first = runner.invoke(app, ["scan", "--target", "https://example.com/"], input="y\n")
    second = runner.invoke(app, ["scan", "--target", "https://example.com:443/"])

    assert first.exit_code == 0, strip_ansi(first.output)
    assert second.exit_code == 0, strip_ansi(second.output)
    assert "Scope already confirmed" in strip_ansi(second.output)


def test_scan_decline_stops_before_starting_or_caching(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        "finlexpurple.scope.confirm.user_config_directory", lambda: tmp_path / "user-config"
    )
    result = runner.invoke(app, ["scan", "--target", "https://example.com/"], input="n\n")
    output = strip_ansi(result.output)

    assert result.exit_code == 1
    assert "Scope was not confirmed; no scan was started." in output
    assert "Scanning is not implemented" not in output
    assert not (tmp_path / "user-config").exists()


def test_scan_confirms_local_directory_target_through_same_flow(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        "finlexpurple.scope.confirm.user_config_directory", lambda: tmp_path / "user-config"
    )
    target_dir = tmp_path / "MiXeDProject"
    target_dir.mkdir()
    result = runner.invoke(app, ["scan", "--target", str(target_dir)], input="y\n")
    output = strip_ansi(result.output)

    assert result.exit_code == 0, output
    assert f"Resolved target: {target_dir.resolve()}" in output
    assert "Scope confirmed. Scanning is not implemented yet." in output


def test_scan_rejects_invalid_target(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        "finlexpurple.scope.confirm.user_config_directory", lambda: tmp_path / "user-config"
    )
    result = runner.invoke(app, ["scan", "--target", "ftp://example.com/"])

    assert result.exit_code == 2
    assert "Invalid target" in strip_ansi(result.output)
    assert not (tmp_path / "user-config").exists()


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
