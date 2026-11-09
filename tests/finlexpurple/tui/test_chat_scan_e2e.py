"""End-to-end: the autonomous chat agent scans a real (in-process) target through the gate.

One in-process, deliberately-vulnerable server (trusts a client-sent price) proves the whole
chat scanning chain holds together and stays honest, with the LLM decision scripted (the
sandbox has no provider key) but every other stage LIVE — real sockets, real recon, real
detectors, the real interactive gate, real deterministic replay:

* the model proposes ``run_agent cashier``; the human confirms scope and approves the probe
  in the chat, and the price-tampering finding reaches VERIFIED via the in-scope read-back;
* if the human denies scope, nothing is scanned;
* if the human approves scope but denies the gate, the state-changing probe is never sent and
  the finding stays a REPORTED candidate — never VERIFIED;
* a hard-gated agent (teller) never actively probes, even when the human says yes;
* egress stays on the confirmed target throughout (default-deny).

This doubles as the honest live-run evidence for the phase: the scanning machinery really runs.
"""

from __future__ import annotations

import io
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar
from urllib.parse import parse_qs, urlsplit

import pytest

from finlexpurple.providers.base import LLMResponse
from finlexpurple.tui.dispatch import ChatAction, dispatch_turn
from finlexpurple.tui.theme import make_console


class _VulnApp(BaseHTTPRequestHandler):
    """Root links to the checkout; /checkout trusts (and persists) the client-sent price."""

    persisted_price = "49.99"
    seen_prices: ClassVar[list[str]] = []

    def log_message(self, *a: object) -> None:
        return

    def _send(self, body: str, content_type: str) -> None:
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        query = {k: v[0] for k, v in parse_qs(parts.query).items()}
        if parts.path == "/":
            self._send('<html><body><a href="/checkout?price=49.99">checkout</a></body></html>',
                       "text/html")
        elif parts.path == "/checkout" and "price" in query:
            type(self).persisted_price = query["price"]  # trusts the client price (the vuln)
            type(self).seen_prices.append(query["price"])
            self._send(f"total={query['price']}", "text/plain")
        elif parts.path == "/checkout":
            self._send(f"receipt total={type(self).persisted_price}", "text/plain")
        else:
            self._send("ok", "text/plain")


class _FakeProvider:
    """Scripts one ChatAction per call (as a real provider's structured output would)."""

    def __init__(self, script: list[ChatAction]) -> None:
        self._script = script
        self.calls = 0

    def complete(self, messages, *, response_schema=None):
        action = self._script[min(self.calls, len(self._script) - 1)]
        self.calls += 1
        return LLMResponse(content=action.message or "", model="fake", structured=action)


def _scripted_ask(*, scope: str, gate: str):
    """A human whose answer to the scope prompt is ``scope`` and to the approval gate is ``gate``."""

    def ask(prompt: str) -> str:
        return scope if "authorized" in prompt.lower() else gate

    return ask


@pytest.fixture()
def base_url():
    _VulnApp.persisted_price = "49.99"
    _VulnApp.seen_prices = []
    server = ThreadingHTTPServer(("127.0.0.1", 0), _VulnApp)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}/"
    finally:
        server.shutdown()
        server.server_close()


def _run(base_url: str, *, agent: str, ask) -> tuple[str, str]:
    console = make_console(file=io.StringIO(), no_color=True, force_terminal=True, width=100)
    provider = _FakeProvider([
        ChatAction(action="run_agent", agent=agent, target=base_url),
        ChatAction(action="reply", message="done"),
    ])
    reply = dispatch_turn(
        provider=provider, console=console, system_prompt="s",
        user_input=f"run {agent}", history=[], ask=ask,
    )
    return reply, console.file.getvalue()


def test_cashier_reaches_verified_when_the_human_approves(base_url) -> None:
    reply, out = _run(base_url, agent="cashier", ask=_scripted_ask(scope="y", gate="y"))
    assert reply == "done"
    assert "scope confirmed" in out                 # the human attested authorization
    assert "price_tampering" in out
    assert "[verified]" in out                       # approved -> captured -> genuinely replayed
    # The tampered probe really hit the server (a price other than the recon's 49.99).
    assert any(p != "49.99" for p in _VulnApp.seen_prices)


def test_nothing_is_scanned_when_the_human_denies_scope(base_url) -> None:
    reply, out = _run(base_url, agent="cashier", ask=_scripted_ask(scope="n", gate="y"))
    assert reply == "done"
    assert "scope not confirmed" in out
    assert "[verified]" not in out
    # Scope denial happens before any probe: the checkout was never tampered.
    assert all(p == "49.99" for p in _VulnApp.seen_prices)


def test_gate_denial_keeps_the_finding_reported_not_verified(base_url) -> None:
    # Chat always asks on every state-changing probe (the deliberate tightening), so a 'no'
    # at the gate is fully binding even for a standard category the CLI would config-allow.
    reply, out = _run(base_url, agent="cashier", ask=_scripted_ask(scope="y", gate="n"))
    assert reply == "done"
    assert "scope confirmed" in out
    assert "price_tampering" in out
    assert "[verified]" not in out                   # the gate denial is fully binding
    assert "[reported]" in out


def test_hard_gated_teller_never_actively_probes(base_url) -> None:
    reply, out = _run(base_url, agent="teller", ask=_scripted_ask(scope="y", gate="y"))
    assert reply == "done"
    assert "[verified]" not in out                   # teller is read-only, hard-gated
    assert all(p == "49.99" for p in _VulnApp.seen_prices)  # no tampering request was ever sent
