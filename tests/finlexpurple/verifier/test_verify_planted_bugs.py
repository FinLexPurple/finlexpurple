"""Phase 11 §5a: verify planted bugs by real re-execution.

A deliberately vulnerable app carries planted SQLi, IDOR, and SSRF bugs; the
engine re-executes each and marks it `verified`. XSS is verified via a headless
browser, which is not available in this environment, so its live path is
exercised with a fake browser runner (the real browser is a flagged external
dependency). A class with no replay engine stays `reported`.
"""

from __future__ import annotations

import threading
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import pytest

from finlexpurple.detectors.prober import HttpProber
from finlexpurple.detectors.schema import Finding, FindingStatus
from finlexpurple.security.egress_policy import EgressPolicy
from finlexpurple.verifier import engine
from finlexpurple.verifier.replay.canary import HttpCanary


class _PlantedBugHandler(BaseHTTPRequestHandler):
    def log_message(self, *args: object) -> None:
        return

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        query = {k: v[0] for k, v in parse_qs(parts.query).items()}
        if parts.path == "/search":  # planted SQLi
            body = "You have an error in your SQL syntax near ''" if "'" in query.get("q", "") else "ok"
        elif parts.path == "/item":  # planted IDOR: same object regardless of session
            body = "secret record for object 1"
        elif parts.path == "/fetch":  # planted SSRF: the server fetches the url param
            try:
                # The vulnerable target deliberately fetches an attacker-supplied URL.
                urllib.request.urlopen(query.get("url", ""), timeout=3).read()
            except OSError:
                pass
            body = "fetched"
        else:
            body = "not found"
        data = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)


@pytest.fixture
def planted_app():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _PlantedBugHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_address[1]}"
    finally:
        server.shutdown()
        server.server_close()


def _prober() -> HttpProber:
    return HttpProber(EgressPolicy.for_run(target_hosts=["127.0.0.1"]))


def test_sqli_marked_verified(planted_app: str) -> None:
    finding = Finding.new(vulnerability_class="sqli", method="GET", url=planted_app + "/search", payload="q='")
    engine.verify(finding, prober=_prober())
    assert finding.status is FindingStatus.VERIFIED


def test_idor_marked_verified(planted_app: str) -> None:
    finding = Finding.new(vulnerability_class="idor", method="GET", url=planted_app + "/item", payload="id=1|2")
    engine.verify(finding, prober=_prober(), sessions=({"X-User": "owner"}, {"X-User": "other"}))
    assert finding.status is FindingStatus.VERIFIED


def test_ssrf_marked_verified_via_out_of_band_canary(planted_app: str) -> None:
    finding = Finding.new(vulnerability_class="ssrf", method="GET", url=planted_app + "/fetch", payload="url=<x>")
    with HttpCanary() as canary:
        egress = EgressPolicy.for_run(target_hosts=["127.0.0.1"])
        engine.verify(finding, prober=HttpProber(egress), canary=canary)
    assert finding.status is FindingStatus.VERIFIED
    assert "out-of-band" in (finding.verification_log or "")


def test_xss_verified_with_browser_runner_fake() -> None:
    # Live XSS verification needs a headless browser (not available here); the
    # replay decision logic is exercised with a fake runner that reports DOM execution.
    finding = Finding.new(vulnerability_class="xss", method="GET", url="https://t.invalid/x", payload="name=<s>")
    engine.verify(finding, browser_runner=lambda url, marker: True)
    assert finding.status is FindingStatus.VERIFIED


def test_no_replay_class_stays_reported() -> None:
    finding = Finding.new(vulnerability_class="generic_misconfig", method="GET", url="u", payload="x")
    engine.verify(finding)
    assert finding.status is FindingStatus.REPORTED
