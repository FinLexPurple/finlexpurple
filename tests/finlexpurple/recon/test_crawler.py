"""Integration checks for bounded recon against local controlled HTTP sites."""

from __future__ import annotations

import logging
import threading
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from typer.testing import CliRunner
from typing_extensions import Self

from finlexpurple.cli import app
from finlexpurple.recon import crawler
from finlexpurple.recon.crawler import USER_AGENT, run_recon
from finlexpurple.scope.models import ScopeDefinition, Target


class _Site:
    def __init__(self, second_port: int = 0, include_redirect: bool = True) -> None:
        self.second_port = second_port
        self.include_redirect = include_redirect
        self.counts: Counter[str] = Counter()
        site = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                path = urlsplit(self.path).path
                site.counts[path] += 1
                if self.headers.get("User-Agent") != USER_AGENT:
                    self.send_error(400)
                    return
                if path == "/robots.txt":
                    self.respond(200, "text/plain", "User-agent: *\nDisallow: /private\n")
                elif path == "/":
                    self.respond(
                        200,
                        "text/html",
                        '<div id="__next"></div>'
                        '<a href="/about">About</a>'
                        '<a href="/search?q=sample&access_token=do-not-log">Search</a>'
                        '<a href="/private">Private</a>'
                        '<a href="ftp://127.0.0.1/file">FTP</a>'
                        '<form action="/submit" method="post">'
                        '<input name="email"><input type="hidden" name="csrf_token" value="secret">'
                        '</form>'
                        + ('<a href="/redirect">Redirect</a>' if site.include_redirect else ""),
                        server="FinLexReconDemo/1.0",
                    )
                elif path == "/redirect":
                    self.send_response(302)
                    self.send_header("Location", f"http://127.0.0.1:{site.second_port}/outside")
                    self.end_headers()
                else:
                    self.respond(200, "text/html", "<main>page</main>")

            def do_POST(self) -> None:
                site.counts["POST " + urlsplit(self.path).path] += 1
                self.send_error(500)

            def respond(self, status: int, content_type: str, body: str, server: str = "Demo") -> None:
                data = body.encode()
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Server", server)
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, format: str, *args: object) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    def __enter__(self) -> Self:
        self.thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class _OutsideSite:
    def __init__(self) -> None:
        self.count = 0

        class Handler(BaseHTTPRequestHandler):
            def do_GET(inner_self) -> None:
                self.count += 1
                inner_self.send_response(200)
                inner_self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self) -> int:
        return int(self.server.server_address[1])

    def __enter__(self) -> Self:
        self.thread.start()
        return self

    def __exit__(self, *args: object) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


def _serve_pair(*, include_redirect: bool = True):
    outside = _OutsideSite()
    inside = _Site(outside.port, include_redirect=include_redirect)
    return outside, inside


def test_crawl_catalogs_pages_forms_and_fingerprints_without_leaking_query_values(
    caplog, monkeypatch
) -> None:
    outside, site = _serve_pair()
    events: list[tuple[str, str]] = []
    actual_enforce = crawler.enforce_scope
    actual_request = crawler._request

    def checked(scope, destination):
        events.append(("scope", str(destination)))
        return actual_enforce(scope, destination)

    def requested(scope, url, **kwargs):
        assert events[-1][0] == "scope"
        events.append(("request", url))
        return actual_request(scope, url, **kwargs)

    monkeypatch.setattr(crawler, "enforce_scope", checked)
    monkeypatch.setattr(crawler, "_request", requested)
    with outside, site:
        root = f"http://127.0.0.1:{site.port}/"
        scope = ScopeDefinition.for_target(Target.parse(root))
        with caplog.at_level(logging.INFO, logger="finlexpurple.recon.crawler"):
            result = run_recon(scope, root, request_delay=0)

    assert result.pages_visited == 5
    assert len(result.catalog) == 6
    by_key = {(item.method, item.url): item for item in result.catalog.endpoints}
    assert ("GET", f"http://127.0.0.1:{site.port}/about") in by_key
    search = by_key[("GET", f"http://127.0.0.1:{site.port}/search")]
    assert search.parameters == ("access_token", "q")
    form = by_key[("POST", f"http://127.0.0.1:{site.port}/submit")]
    assert form.parameters == ("csrf_token", "email")
    assert "Next.js" in result.fingerprint.technologies
    assert "FinLexReconDemo/1.0" in (result.fingerprint.server or "")
    assert result.disallow_paths == ("/private",)
    assert outside.count == 0
    assert sum(event[0] == "request" for event in events) == result.requests_made
    assert "do-not-log" not in caplog.text
    assert "[REDACTED]" in caplog.text
    assert site.counts["POST /submit"] == 0
    assert site.counts["/private"] == 1


def test_respect_robots_skips_disallowed_pages_but_default_only_records_hints() -> None:
    outside, site = _serve_pair()
    with outside, site:
        root = f"http://127.0.0.1:{site.port}/"
        scope = ScopeDefinition.for_target(Target.parse(root))
        result = run_recon(scope, root, request_delay=0, respect_robots=True)

    assert result.disallow_paths == ("/private",)
    assert site.counts["/private"] == 0
    assert result.pages_visited == 4


def test_network_scope_checks_resolved_peer_ip_before_connecting() -> None:
    outside, site = _serve_pair(include_redirect=False)
    with outside, site:
        root = f"http://localhost:{site.port}/"
        network_scope = ScopeDefinition.for_target(Target.parse("127.0.0.0/8"))
        result = run_recon(network_scope, root, request_delay=0)

    assert result.pages_visited == 4
    assert site.counts["/"] == 1
    assert outside.count == 0


def test_network_scope_rejects_dns_answers_outside_cidr_before_any_http_request(caplog) -> None:
    outside, site = _serve_pair()
    with outside, site:
        root = f"http://localhost:{site.port}/"
        network_scope = ScopeDefinition.for_target(Target.parse("192.0.2.0/24"))
        result = run_recon(network_scope, root, request_delay=0)

    assert result.pages_visited == 0
    assert site.counts == Counter()
    assert "no permitted address" in caplog.text


def test_request_delay_is_applied_between_http_requests(monkeypatch) -> None:
    scope = ScopeDefinition.for_target(Target.parse("https://example.com/"))
    sleep_calls: list[float] = []
    monkeypatch.setattr(crawler.time, "sleep", sleep_calls.append)

    def fake_request(scope, url, **kwargs):
        if url.endswith("robots.txt"):
            return 200, {"content-type": "text/plain"}, b""
        if url.endswith("/a"):
            return 200, {"content-type": "text/html"}, b"<p>child</p>"
        return 200, {"content-type": "text/html"}, b'<a href="/a">child</a>'

    monkeypatch.setattr(crawler, "_request", fake_request)

    result = run_recon(scope, "https://example.com/", request_delay=0.5)

    assert result.pages_visited == 2
    assert len(sleep_calls) == 2
    assert all(0 <= delay <= 0.5 for delay in sleep_calls)


def test_scan_cli_runs_the_crawler_and_reports_the_safe_catalog(monkeypatch) -> None:
    outside, site = _serve_pair()
    with outside, site:
        root = f"http://127.0.0.1:{site.port}/"
        scope = ScopeDefinition.for_target(Target.parse(root))
        monkeypatch.setattr("finlexpurple.cli.confirm_scope", lambda target, **kwargs: scope)

        result = CliRunner().invoke(
            app,
            ["scan", "--target", root, "--request-delay", "0"],
        )

    assert result.exit_code == 0, result.output
    assert "Recon: discovered 6 endpoints." in result.output
    assert "POST http://127.0.0.1" in result.output
    assert "Parameters: access_token, q" in result.output
    assert "demo-secret" not in result.output
    assert "robots.txt Disallow: /private" in result.output
    assert outside.count == 0


def test_looks_like_html_sniffs_bare_markup_and_rejects_non_html() -> None:
    # Regression (Bug 2): a page served with no/ambiguous Content-Type must still
    # be recognized as HTML so its links are crawled; real non-HTML is rejected.
    from finlexpurple.recon.crawler import _looks_like_html

    assert _looks_like_html('<a href="/search?q=t">s</a>') is True
    assert _looks_like_html("<!DOCTYPE html><html><body>x</body></html>") is True
    assert _looks_like_html('<form action="/submit"></form>') is True
    assert _looks_like_html('{"findings": [], "note": "no markup here"}') is False
    assert _looks_like_html("just some plain text") is False
