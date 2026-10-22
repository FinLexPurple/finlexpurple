"""Send a telemetry payload — only when explicitly enabled (decisions.md §8).

Hard rules enforced here:

* **Off by default.** If ``Config.telemetry_enabled`` is false, ``send`` makes no
  network call at all and returns a disabled result. Telemetry is never sent in
  the background — only an explicit command calls this.
* **Allow-list gate.** A payload containing any key outside the allow-list is a
  bug; ``send`` raises :class:`TelemetryPayloadError` rather than transmit it.
* **No hardcoded endpoint.** The destination comes from
  ``Config.telemetry_endpoint``; with none configured, nothing is sent.

The HTTP transport is injectable so tests assert, with the real network mocked,
that nothing is transmitted when telemetry is off.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from finlexpurple.config import Config
from finlexpurple.telemetry import allowlist

# (endpoint, payload) -> HTTP status code.
Transport = Callable[[str, dict[str, Any]], int]


class TelemetryPayloadError(ValueError):
    """A payload contained a field outside the allow-list; refusing to send."""


@dataclass(frozen=True)
class SendResult:
    """The outcome of a send attempt; ``sent`` is false when nothing left the host."""

    sent: bool
    reason: str
    status_code: int | None = None


def _default_transport(endpoint: str, payload: dict[str, Any]) -> int:
    import httpx

    response = httpx.post(endpoint, json=payload, timeout=10.0)
    return response.status_code


def send(payload: dict[str, Any], *, config: Config, transport: Transport | None = None) -> SendResult:
    """Send ``payload`` only if telemetry is enabled, allow-listed, and has an endpoint."""

    extra = allowlist.disallowed_keys(payload)
    if extra:
        # Loud failure: a disallowed key must never be transmitted.
        raise TelemetryPayloadError(f"payload contains non-allow-listed field(s): {sorted(extra)}")
    if not config.telemetry_enabled:
        return SendResult(sent=False, reason="telemetry is disabled (off by default); nothing sent.")
    if not config.telemetry_endpoint:
        return SendResult(sent=False, reason="no telemetry endpoint configured; nothing sent.")
    status = (transport or _default_transport)(config.telemetry_endpoint, payload)
    return SendResult(sent=True, reason="telemetry sent.", status_code=status)
