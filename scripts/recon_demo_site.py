"""Two local HTTP sites for manually checking Phase 5 scope enforcement."""

from __future__ import annotations

import argparse
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit


def serve(inside_port: int, outside_port: int) -> None:
    """Serve a linked test site and a second-port redirect canary."""

    class InsideHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            path = urlsplit(self.path).path
            print(f"IN_SCOPE_REQUEST GET {path}", flush=True)
            if path == "/robots.txt":
                self._respond(200, "text/plain", "User-agent: *\nDisallow: /private\n")
            elif path == "/":
                self._respond(
                    200,
                    "text/html",
                    """<!doctype html><html><body><div id="__next"></div>
                    <a href="/about">About</a>
                    <a href="/search?q=example&access_token=demo-secret">Search</a>
                    <a href="/private">Robots hint</a><a href="/redirect">Redirect check</a>
                    <form action="/submit" method="post"><input name="email">
                    <input name="csrf_token" type="hidden" value="not-submitted"></form>
                    </body></html>""",
                )
            elif path == "/redirect":
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{outside_port}/must-not-be-requested")
                self.end_headers()
            else:
                self._respond(200, "text/html", "<!doctype html><html><body>Demo page</body></html>")

        def do_POST(self) -> None:
            print(f"UNEXPECTED_POST {urlsplit(self.path).path}", flush=True)
            self.send_error(405)

        def _respond(self, status: int, content_type: str, body: str) -> None:
            data = body.encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Server", "FinLexPurple-Recon-Demo/1.0")
            self.end_headers()
            self.wfile.write(data)

        def log_message(self, format: str, *args: object) -> None:
            return

    class OutsideHandler(BaseHTTPRequestHandler):
        def do_GET(self) -> None:
            print(f"OUT_OF_SCOPE_REQUEST GET {urlsplit(self.path).path}", flush=True)
            self.send_response(200)
            self.end_headers()

        def log_message(self, format: str, *args: object) -> None:
            return

    inside = ThreadingHTTPServer(("127.0.0.1", inside_port), InsideHandler)
    outside = ThreadingHTTPServer(("127.0.0.1", outside_port), OutsideHandler)
    print(f"In-scope test site: http://127.0.0.1:{inside.server_port}/", flush=True)
    print(f"Out-of-scope canary: http://127.0.0.1:{outside.server_port}/", flush=True)
    print("Stop both servers with Ctrl+C. OUT_OF_SCOPE_REQUEST must never appear.", flush=True)
    threads = [
        threading.Thread(target=inside.serve_forever, daemon=True),
        threading.Thread(target=outside.serve_forever, daemon=True),
    ]
    for thread in threads:
        thread.start()
    try:
        for thread in threads:
            thread.join()
    except KeyboardInterrupt:
        pass
    finally:
        inside.shutdown()
        outside.shutdown()
        inside.server_close()
        outside.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inside-port", type=int, default=8765)
    parser.add_argument("--outside-port", type=int, default=8766)
    args = parser.parse_args()
    if args.inside_port == args.outside_port:
        parser.error("the inside and outside ports must differ")
    serve(args.inside_port, args.outside_port)


if __name__ == "__main__":
    main()
