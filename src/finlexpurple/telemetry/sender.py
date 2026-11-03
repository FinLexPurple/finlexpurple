"""Send a telemetry payload — only when explicitly enabled (decisions.md §8).

Hard rules enforced here:

* **Off by default.** If ``Config.telemetry_enabled`` is false, ``send`` makes no
  network call at all and returns a disabled result. Telemetry is never sent in
  the background — only an explicit command calls this.
* **Opt-out kill-switch (Unit 1.5).** An active opt-out forces telemetry **off
  even when it is otherwise enabled**: ``FINLEXPURPLE_TELEMETRY`` set to a falsey
  value, or the widely-honoured ``DO_NOT_TRACK=1`` convention. Air-gapped
  deployments set one of these; combined with "only an explicit command sends,
  never in the background", nothing leaves such a host.
* **Allow-list gate.** A payload containing any key outside the allow-list
  (top-level or inside ``props``) is a bug; ``send`` raises
  :class:`TelemetryPayloadError` rather than transmit it.
* **No hardcoded endpoint.** The destination comes from
  ``Config.telemetry_endpoint``; with none configured, nothing is sent.

The HTTP transport is injectable so tests assert, with the real network mocked,
that nothing is transmitted when telemetry is off.
"""

from __future__ import annotations

import os
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import Any

from finlexpurple.config import Config
from finlexpurple.telemetry import allowlist

# (endpoint, payload) -> HTTP status code.
Transport = Callable[[str, dict[str, Any]], int]

# The frozen opt-out conventions (Unit 1.5). FINLEXPURPLE_TELEMETRY is the
# project's own kill-switch; DO_NOT_TRACK is the common cross-tool convention.
TELEMETRY_OPT_OUT_ENV = "FINLEXPURPLE_TELEMETRY"
DO_NOT_TRACK_ENV = "DO_NOT_TRACK"
_OPT_OUT_VALUES = frozenset({"0", "false", "off", "no", "disabled"})
_TRUE_VALUES = frozenset({"1", "true", "yes", "on"})


def telemetry_opt_out_active(env: Mapping[str, str] | None = None) -> bool:
    """True if an opt-out forces telemetry off regardless of ``telemetry_enabled``.

    Active when ``DO_NOT_TRACK`` is truthy, or when ``FINLEXPURPLE_TELEMETRY`` is
    present and set to a falsey value. ``FINLEXPURPLE_TELEMETRY`` is only a
    kill-switch: a truthy value does not opt a user *in* — consent still comes
    solely from ``telemetry_enabled`` — it merely declines to block.
    """

    source = os.environ if env is None else env
    if source.get(DO_NOT_TRACK_ENV, "").strip().lower() in _TRUE_VALUES:
        return True
    flp = source.get(TELEMETRY_OPT_OUT_ENV)
    return flp is not None and flp.strip().lower() in _OPT_OUT_VALUES


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
    if telemetry_opt_out_active():
        return SendResult(
            sent=False,
            reason="telemetry opt-out is active (FINLEXPURPLE_TELEMETRY/DO_NOT_TRACK); nothing sent.",
        )
    if not config.telemetry_enabled:
        return SendResult(sent=False, reason="telemetry is disabled (off by default); nothing sent.")
    if not config.telemetry_endpoint:
        return SendResult(sent=False, reason="no telemetry endpoint configured; nothing sent.")
    status = (transport or _default_transport)(config.telemetry_endpoint, payload)
    return SendResult(sent=True, reason="telemetry sent.", status_code=status)
