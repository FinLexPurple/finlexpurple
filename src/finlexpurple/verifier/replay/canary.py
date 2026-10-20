"""Out-of-band canary for SSRF verification (Phase 11; decisions.md §6).

SSRF is confirmed only by a real out-of-band callback: the replay injects the
canary's URL and the test passes only if the *target itself* reaches that URL.
``HttpCanary`` is a local listener that records a hit bearing its unique token;
a deployment uses a public listener implementing the same small protocol.
"""

from __future__ import annotations

import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from types import TracebackType
from typing import Protocol, runtime_checkable


@runtime_checkable
class OutOfBandCanary(Protocol):
    """A URL to inject and a way to ask whether it was actually reached."""

    @property
    def url(self) -> str: ...

    def triggered(self) -> bool: ...


class HttpCanary:
    """A local HTTP listener that records whether its token-bearing URL was fetched."""

    def __init__(self) -> None:
        self._token = secrets.token_hex(8)
        self._hit = False
        canary = self

        class _Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: object) -> None:
                return

            def do_GET(self) -> None:
                if canary._token in self.path:
                    canary._hit = True
                self.send_response(200)
                self.end_headers()

        self._server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    @property
    def url(self) -> str:
        # Bound to 127.0.0.1 in __init__; only the ephemeral port varies.
        port = self._server.server_address[1]
        return f"http://127.0.0.1:{port}/{self._token}"

    def triggered(self) -> bool:
        return self._hit

    def __enter__(self) -> HttpCanary:  # noqa: PYI034 - `Self` is 3.11+, project targets 3.10
        self._thread.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._server.shutdown()
        self._server.server_close()
