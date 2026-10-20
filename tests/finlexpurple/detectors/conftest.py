"""Shared test helpers for Phase 10 detectors: a fake prober and a vulnerable app."""

from __future__ import annotations

import threading
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from finlexpurple.detectors.prober import ProbeResponse

Responder = Callable[[str, str, dict[str, str], dict[str, str]], ProbeResponse]


class FakeProber:
    """A deterministic prober that returns whatever a responder callable produces."""

    def __init__(self, responder: Responder) -> None:
        self._responder = responder
        self.calls: list[tuple[str, str, dict[str, str], dict[str, str]]] = []

    def request(self, method, url, *, params=None, headers=None) -> ProbeResponse:
        params = params or {}
        headers = headers or {}
        self.calls.append((method, url, params, headers))
        return self._responder(method, url, params, headers)


@pytest.fixture
def prober_factory() -> Callable[[Responder], FakeProber]:
    """Return a factory that builds a FakeProber from a responder callable."""

    return lambda responder: FakeProber(responder)


class _VulnHandler(BaseHTTPRequestHandler):
    """A deliberately vulnerable app covering the four MVP classes."""

    def log_message(self, *args: object) -> None:  # silence test server logging
        return

    def _send(self, status: int, content_type: str, body: str, extra: dict[str, str] | None = None) -> None:
        data = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Server", "VulnTest/1.0")  # version banner (generic_misconfig)
        for key, value in (extra or {}).items():
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        path = parts.path
        query = {k: v[0] for k, v in parse_qs(parts.query).items()}
        xfh = self.headers.get("X-Forwarded-Host")
        if path == "/search":  # SQLi: a quote triggers a SQL error echo
            q = query.get("q", "")
            if "'" in q:
                self._send(500, "text/html", "You have an error in your SQL syntax near ''")
            else:
                self._send(200, "text/html", f"<p>results for {q}</p>")
        elif path == "/greet":  # XSS: reflects name unescaped into HTML
            self._send(200, "text/html", f"<h1>Hello {query.get('name', '')}</h1>")
        elif path == "/item":  # IDOR: different body per id, both 200
            self._send(200, "text/plain", f"record for user id={query.get('id', '?')}")
        elif path == "/fetch":  # SSRF surface: a url parameter
            self._send(200, "text/plain", "fetched")
        elif path == "/login":  # auth_misconfig: insecure cookie
            self._send(200, "text/html", "ok", extra={"Set-Cookie": "session=abc123; Path=/"})
        elif path == "/cache":  # cache poisoning: reflects X-Forwarded-Host
            self._send(200, "text/html", f"<base href='{xfh}'>")
        else:
            self._send(404, "text/plain", "not found")


@pytest.fixture
def vulnerable_server():
    """Run the deliberately vulnerable app on localhost; yield its base URL."""

    server = ThreadingHTTPServer(("127.0.0.1", 0), _VulnHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    host, port = server.server_address[0], server.server_address[1]
    try:
        yield f"http://{host}:{port}"
    finally:
        server.shutdown()
        server.server_close()
