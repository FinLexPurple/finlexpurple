"""Phase 17: the sender sends only when enabled, allow-listed, with an endpoint."""

from __future__ import annotations

import pytest

from finlexpurple.config import Config
from finlexpurple.telemetry.sender import SendResult, TelemetryPayloadError, send


def _config(*, enabled: bool, endpoint: str | None) -> Config:
    return Config.model_construct(telemetry_enabled=enabled, telemetry_endpoint=endpoint)


def test_disabled_by_default_makes_no_network_call() -> None:
    calls: list[tuple[str, dict]] = []

    def transport(url, payload):
        calls.append((url, payload))
        return 200

    result = send({"event": "install", "install_id": "x"},
                  config=_config(enabled=False, endpoint="https://example.invalid/t"),
                  transport=transport)
    assert result.sent is False
    assert calls == []  # the transport was never invoked


def test_enabled_with_endpoint_sends() -> None:
    calls: list[tuple[str, dict]] = []

    def transport(url, payload):
        calls.append((url, payload))
        return 202

    result = send({"event": "install", "install_id": "x"},
                  config=_config(enabled=True, endpoint="https://example.invalid/t"),
                  transport=transport)
    assert result == SendResult(sent=True, reason="telemetry sent.", status_code=202)
    assert len(calls) == 1


def test_enabled_without_endpoint_sends_nothing() -> None:
    result = send({"event": "install"}, config=_config(enabled=True, endpoint=None),
                  transport=lambda u, p: 200)
    assert result.sent is False


def test_disallowed_payload_is_refused_even_when_enabled() -> None:
    with pytest.raises(TelemetryPayloadError):
        send({"event": "x", "url": "http://leak"},
             config=_config(enabled=True, endpoint="https://example.invalid/t"),
             transport=lambda u, p: 200)
