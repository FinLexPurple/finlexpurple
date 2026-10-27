"""CLI behavior tests."""

from __future__ import annotations

import re
from types import SimpleNamespace

from typer.testing import CliRunner

from finlexpurple import cli
from finlexpurple.cli import app
from finlexpurple.recon.endpoint_catalog import EndpointCatalog
from finlexpurple.recon.fingerprint import Fingerprint

runner = CliRunner()
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def strip_ansi(output: str) -> str:
    return _ANSI_ESCAPE.sub("", output)


def stub_recon_result():
    return SimpleNamespace(
        catalog=EndpointCatalog(),
        fingerprint=Fingerprint(server=None, technologies=()),
        disallow_paths=(),
        warnings=(),
    )


def test_help_lists_registered_subcommands() -> None:
    result = runner.invoke(app, ["--help"])
    output = strip_ansi(result.stdout)

    assert result.exit_code == 0
    for command in ("setup", "init", "scan", "telemetry", "feedback"):
        assert command in output
    assert "--json-logs" in output


def test_version_prints_semver_and_codename() -> None:
    from finlexpurple import __version__
    from finlexpurple.release import codename_for

    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    out = strip_ansi(result.stdout).strip()
    # Canonical semver is present (not replaced), with the cosmetic codename (§16).
    assert __version__ in out
    assert codename_for(__version__) in out


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
    monkeypatch.setattr(
        "finlexpurple.cli.confirm_scope", lambda target, **kwargs: SimpleNamespace(first_confirmed_at=None)
    )
    monkeypatch.setattr("finlexpurple.cli.run_recon", lambda *args, **kwargs: stub_recon_result())

    commands = (
        ["setup"],
        ["scan", "--target", "https://example.com/"],
        ["telemetry", "show"],
    )
    for command in commands:
        result = runner.invoke(app, ["--json-logs", *command])
        assert result.exit_code == 0

    assert seen == [True, True, True]


def test_scan_requires_target_option() -> None:
    result = runner.invoke(app, ["scan"])

    assert result.exit_code == 2
    assert "--target" in strip_ansi(result.output)


def test_scan_resume_revalidates_saved_target_scope_and_skips_recon(tmp_path, monkeypatch) -> None:
    """`scan --resume` re-confirms scope, does not rerun recon, and drives the engine.

    Asserts recon is never invoked on resume (the monkeypatched run_recon raises if
    called) and that a report-stage run completes, demonstrating resume continues
    from saved state rather than restarting.
    """

    from datetime import datetime, timezone

    from finlexpurple.orchestrator.persistence import create_run_directory, save_state
    from finlexpurple.orchestrator.state import RunState

    monkeypatch.setattr(
        "finlexpurple.scope.confirm.user_config_directory", lambda: tmp_path / "user-config"
    )
    run_id, directory = create_run_directory(
        "https://example.com/", reports_dir=tmp_path / "reports",
        now=datetime(2026, 10, 19, tzinfo=timezone.utc),
    )
    state = RunState(
        run_id=run_id,
        canonical_target="https://example.com/",
        current_stage="report",
    )
    state_path = directory / "run-state.json"
    save_state(state_path, state)
    monkeypatch.setattr(
        "finlexpurple.cli.run_recon",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("recon must not rerun")),
    )

    result = runner.invoke(app, ["scan", "--resume", str(state_path)], input="y\n")

    output = strip_ansi(result.output)
    assert result.exit_code == 0, output
    assert "Resolved target: https://example.com/" in output
    assert "Scope confirmation saved locally" in output
    assert "Scan complete" in output  # now end-to-end: writes a report
    assert state_path.exists()


def test_scan_resume_refuses_malformed_file_without_deleting_or_restarting(tmp_path) -> None:
    """A malformed resume file exits 2 with a clear message and is left on disk intact."""

    state_path = tmp_path / "run-state.json"
    state_path.write_text("not json", encoding="utf-8")

    result = runner.invoke(app, ["scan", "--resume", str(state_path)])

    output = strip_ansi(result.output)
    assert result.exit_code == 2
    assert "Cannot resume" in output
    assert state_path.read_text(encoding="utf-8") == "not json"


def test_scan_confirms_scope_then_runs_recon_stage(tmp_path, monkeypatch) -> None:
    monkeypatch.setattr(
        "finlexpurple.scope.confirm.user_config_directory", lambda: tmp_path / "user-config"
    )
    monkeypatch.setattr("finlexpurple.cli.run_recon", lambda *args, **kwargs: stub_recon_result())
    result = runner.invoke(app, ["scan", "--target", "https://example.com/app"], input="y\n")

    output = strip_ansi(result.output)
    assert result.exit_code == 0, output
    assert "Resolved target: https://example.com/app" in output
    assert "Subdomains intended for enumeration: none" in output
    assert "path /app and its descendants" in output
    assert "exact host example.com" in output
    assert "Recon: discovered 0 endpoints." in output
    assert len(list((tmp_path / "user-config").glob("*.json"))) == 1


def test_scan_reconfirms_authorization_every_run(tmp_path, monkeypatch) -> None:
    # A fresh scan re-attests authorization on every run (it does not silently
    # reuse a globally-cached confirmation), so the second run prompts again.
    monkeypatch.setattr(
        "finlexpurple.scope.confirm.user_config_directory", lambda: tmp_path / "user-config"
    )
    monkeypatch.setattr("finlexpurple.cli.run_recon", lambda *args, **kwargs: stub_recon_result())
    first = runner.invoke(app, ["scan", "--target", "https://example.com/"], input="y\n")
    # Same target, a second run: it must prompt again rather than skip on cache.
    second = runner.invoke(app, ["scan", "--target", "https://example.com:443/"], input="y\n")

    assert first.exit_code == 0, strip_ansi(first.output)
    assert second.exit_code == 0, strip_ansi(second.output)
    assert "Do you confirm that you are authorized" in strip_ansi(second.output)
    assert "Scope already confirmed" not in strip_ansi(second.output)


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


def test_scan_rejects_local_directory_target_before_confirmation(tmp_path) -> None:
    target_dir = tmp_path / "MiXeDProject"
    target_dir.mkdir()
    result = runner.invoke(app, ["scan", "--target", str(target_dir)])
    output = strip_ansi(result.output)

    assert result.exit_code == 2
    assert "Web recon requires a URL or IP/CIDR scope" in output


def test_scan_requires_root_url_for_ip_or_cidr_target() -> None:
    result = runner.invoke(app, ["scan", "--target", "192.0.2.0/24"])

    assert result.exit_code == 2
    assert "requires --root-url" in strip_ansi(result.output)


def test_scan_passes_network_root_and_recon_options(monkeypatch, tmp_path) -> None:
    seen: dict[str, object] = {}
    monkeypatch.setattr(
        "finlexpurple.scope.confirm.user_config_directory", lambda: tmp_path / "user-config"
    )

    def fake_recon(scope, root_url, **kwargs):
        seen.update(root_url=root_url, **kwargs)
        return stub_recon_result()

    monkeypatch.setattr("finlexpurple.cli.run_recon", fake_recon)
    result = runner.invoke(
        app,
        [
            "scan",
            "--target",
            "127.0.0.0/8",
            "--root-url",
            "http://127.0.0.1:8080/",
            "--request-delay",
            "0.25",
            "--respect-robots",
        ],
        input="y\n",
    )

    assert result.exit_code == 0, strip_ansi(result.output)
    assert seen == {
        "root_url": "http://127.0.0.1:8080/",
        "request_delay": 0.25,
        "respect_robots": True,
    }


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


def test_doctor_tools_reports_external_scanners() -> None:
    """Phase 7: `doctor --tools` reports wrapped-scanner availability (never execs docker)."""

    result = runner.invoke(app, ["doctor", "--tools"])
    output = strip_ansi(result.output)
    assert result.exit_code == 0, output
    assert "External tools:" in output
    assert "trivy" in output and "osv-scanner" in output and "mcp-scan" in output


def test_setup_isolation_saves_standard_tier(tmp_path, monkeypatch) -> None:
    """Phase 7: the new isolation-tier setup step writes ISOLATION_TIER to .env."""

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr("finlexpurple.security.isolation.docker_available", lambda: True)
    result = runner.invoke(app, ["setup-isolation"], input="standard\n")

    output = strip_ansi(result.output)
    assert result.exit_code == 0, output
    assert "Saved ISOLATION_TIER=standard" in output
    assert "ISOLATION_TIER=standard" in (tmp_path / ".env").read_text(encoding="utf-8")


def test_setup_isolation_none_requires_explicit_confirmation(tmp_path, monkeypatch) -> None:
    """Choosing None warns and only proceeds on an explicit confirm."""

    monkeypatch.chdir(tmp_path)
    # Select 'none', then decline the "run without isolation?" prompt.
    result = runner.invoke(app, ["setup-isolation"], input="none\nn\n")
    output = strip_ansi(result.output)
    assert result.exit_code == 0
    assert "No change made." in output
    assert not (tmp_path / ".env").exists()


def test_setup_isolation_rejects_unknown_tier(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["setup-isolation"], input="ultra\n")
    assert result.exit_code == 2
    assert "Unknown tier" in strip_ansi(result.output)


def _scan_env(tmp_path, monkeypatch) -> None:
    """Make scans write under tmp and use a tmp scope cache with stubbed recon."""

    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(
        "finlexpurple.scope.confirm.user_config_directory", lambda: tmp_path / "cfg"
    )
    monkeypatch.setattr("finlexpurple.cli.run_recon", lambda *a, **k: stub_recon_result())


def test_scan_records_authorization_attestation_and_fix_mode(tmp_path, monkeypatch) -> None:
    """Phase 8: scan records the authorization attestation + fix mode in the run audit log."""

    _scan_env(tmp_path, monkeypatch)
    result = runner.invoke(
        app, ["scan", "--target", "https://example.com/", "--fix-mode", "agent"], input="y\n"
    )
    output = strip_ansi(result.output)
    assert result.exit_code == 0, output
    assert "Authorization attested for https://example.com/" in output
    assert "Fix mode: agent." in output
    audits = list((tmp_path / "finlexpurple-reports").glob("*/audit.jsonl"))
    assert len(audits) == 1
    content = audits[0].read_text(encoding="utf-8")
    assert "authorization_attested" in content and "fix_mode_selected" in content


def test_scan_defaults_fix_mode_to_human(tmp_path, monkeypatch) -> None:
    _scan_env(tmp_path, monkeypatch)
    result = runner.invoke(app, ["scan", "--target", "https://example.com/"], input="y\n")
    assert result.exit_code == 0, strip_ansi(result.output)
    assert "Fix mode: human." in strip_ansi(result.output)


def test_scan_rejects_invalid_fix_mode(tmp_path, monkeypatch) -> None:
    _scan_env(tmp_path, monkeypatch)
    result = runner.invoke(
        app, ["scan", "--target", "https://example.com/", "--fix-mode", "auto"], input="y\n"
    )
    assert result.exit_code == 2
    assert "Invalid --fix-mode" in strip_ansi(result.output)


def test_resume_by_run_id_continues_and_cached_scope_is_not_reprompted(tmp_path, monkeypatch) -> None:
    """Phase 8: `resume <run-id>` resolves the run dir and continues without re-prompting."""

    _scan_env(tmp_path, monkeypatch)
    first = runner.invoke(app, ["scan", "--target", "https://example.com/"], input="y\n")
    assert first.exit_code == 0, strip_ansi(first.output)
    states = list((tmp_path / "finlexpurple-reports").glob("*/run-state.json"))
    assert len(states) == 1
    run_id = states[0].parent.name

    result = runner.invoke(app, ["resume", run_id])  # cached scope -> no prompt
    output = strip_ansi(result.output)
    assert result.exit_code == 0, output
    assert "Scope already confirmed" in output
    assert "Scan complete" in output  # now end-to-end: writes a report
    # The audit chain continued across the two runs and still verifies.
    from finlexpurple.security.audit_log import AuditLog

    assert AuditLog.verify_file(states[0].parent / "audit.jsonl") is True


def test_resume_unknown_run_id_is_rejected(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["resume", "nope-not-a-run"])
    assert result.exit_code == 2
    assert "No run-state.json found" in strip_ansi(result.output)


def test_resume_rejects_traversal_run_id(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    result = runner.invoke(app, ["resume", "../escape"])
    assert result.exit_code == 2
    assert "Invalid run id" in strip_ansi(result.output)
