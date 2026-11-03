"""Unit 1.5: the envelope helpers, the opt-out kill-switch, and install-id reset."""

from __future__ import annotations

from datetime import datetime, timezone

from finlexpurple.config import Config
from finlexpurple.telemetry import envelope
from finlexpurple.telemetry.install_counter import (
    get_or_create_install_id,
    mark_install_ping_sent,
    reset_install_id,
)
from finlexpurple.telemetry.sender import (
    SendResult,
    send,
    telemetry_opt_out_active,
)


def test_ts_day_is_utc_day_granularity_only() -> None:
    # A non-UTC afternoon still reports the correct UTC calendar day.
    moment = datetime(2026, 11, 3, 23, 30, tzinfo=timezone.utc)
    assert envelope.ts_day(moment) == "2026-11-03"
    naive = datetime(2026, 11, 3, 1, 0)  # treated as UTC
    assert envelope.ts_day(naive) == "2026-11-03"


def test_bucket_never_leaks_a_raw_count() -> None:
    assert envelope.bucket(0) == "0"
    assert envelope.bucket(1) == "1-9" and envelope.bucket(9) == "1-9"
    assert envelope.bucket(10) == "10-49" and envelope.bucket(49) == "10-49"
    assert envelope.bucket(50) == "50+" and envelope.bucket(9999) == "50+"


def test_build_envelope_carries_only_coarse_facts() -> None:
    env = envelope.build_envelope(envelope.Event.INSTALL, install_id="id", now=datetime(2026, 1, 2, tzinfo=timezone.utc))
    assert env["schema_version"] == envelope.TELEMETRY_SCHEMA_VERSION
    assert env["event"] == "install" and env["install_id"] == "id"
    assert env["ts_day"] == "2026-01-02" and env["props"] == {}
    assert env["os"] == envelope.os_family()


def _enabled_config() -> Config:
    return Config.model_construct(telemetry_enabled=True, telemetry_endpoint="https://x.invalid/t")


def test_do_not_track_forces_off_even_when_enabled(monkeypatch) -> None:
    monkeypatch.setenv("DO_NOT_TRACK", "1")
    calls: list = []
    result = send({"event": "install", "install_id": "x"}, config=_enabled_config(),
                  transport=lambda u, p: calls.append(1) or 200)
    assert result.sent is False and calls == []
    assert "opt-out" in result.reason


def test_finlexpurple_telemetry_zero_forces_off(monkeypatch) -> None:
    monkeypatch.setenv("FINLEXPURPLE_TELEMETRY", "0")
    result = send({"event": "install", "install_id": "x"}, config=_enabled_config(),
                  transport=lambda u, p: 200)
    assert result.sent is False and "opt-out" in result.reason


def test_truthy_finlexpurple_telemetry_does_not_block(monkeypatch) -> None:
    # A truthy value is not an opt-out; it merely declines to block. Consent still
    # comes from telemetry_enabled, so an enabled config now sends.
    monkeypatch.setenv("FINLEXPURPLE_TELEMETRY", "1")
    monkeypatch.delenv("DO_NOT_TRACK", raising=False)
    assert telemetry_opt_out_active() is False
    result = send({"event": "install", "install_id": "x"}, config=_enabled_config(),
                  transport=lambda u, p: 202)
    assert result == SendResult(sent=True, reason="telemetry sent.", status_code=202)


def test_opt_out_detector_reads_an_explicit_env_mapping() -> None:
    assert telemetry_opt_out_active({"FINLEXPURPLE_TELEMETRY": "off"}) is True
    assert telemetry_opt_out_active({"DO_NOT_TRACK": "yes"}) is True
    assert telemetry_opt_out_active({}) is False


def test_reset_install_id_replaces_the_id_and_clears_the_marker(tmp_path) -> None:
    id_path = tmp_path / "install-id"
    marker = tmp_path / "install-ping-sent"
    first = get_or_create_install_id(id_path)
    mark_install_ping_sent(marker)
    assert marker.exists()

    fresh = reset_install_id(id_path, marker)
    assert fresh != first                 # a genuinely new id
    assert not marker.exists()            # ping marker cleared so the new id can ping
    assert id_path.read_text(encoding="utf-8").strip() == fresh
