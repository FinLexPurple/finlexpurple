"""Realism: the webhook-bypass settlement confirmer reads a SEPARATE order-status oracle.

The confirmer the CLI injects must read durable paid-state from an operator-provided
order-status URL, never by re-reading the webhook endpoint. This proves the three
outcomes it feeds the replay (which maps True/False/None to
REPRODUCED/NOT_REPRODUCED/INCONCLUSIVE) against a real in-process oracle:
oracle-shows-paid -> True, oracle-shows-not-paid -> False, no-oracle/unreachable -> None.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar

from finlexpurple.detectors.prober import HttpProber
from finlexpurple.detectors.schema import Finding
from finlexpurple.finance.payment_tests import webhook_bypass
from finlexpurple.security.egress_policy import EgressPolicy
from finlexpurple.verifier.read_back import settlement_confirmer_for as _settlement_confirmer_for


class _Oracle(BaseHTTPRequestHandler):
    """A separate order-status endpoint: GET /orders/<order_id> -> that order's status."""

    paid: ClassVar[set[str]] = set()

    def log_message(self, *a: object) -> None:
        return

    def do_GET(self) -> None:
        order_id = self.path.rsplit("/", 1)[-1]
        status = webhook_bypass.PAID_MARKER if order_id in type(self).paid else "pending"
        body = f'{{"order_id": "{order_id}", "status": "{status}"}}'.encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


def _finding() -> Finding:
    return Finding.new(
        vulnerability_class="webhook_bypass", method="POST", url="http://t/payment/webhook",
        payload="webhook_bypass:forged", body='{"status": "paid"}', agent="cashier",
    )


def _server():
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Oracle)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_address[1]}"


def test_oracle_shows_paid_confirms_true() -> None:
    _Oracle.paid = {webhook_bypass.FORGED_ORDER_ID}
    server, base = _server()
    try:
        prober = HttpProber(EgressPolicy.for_run(target_hosts=["127.0.0.1"]))
        confirm = _settlement_confirmer_for(prober, f"{base}/orders/{{order_id}}")
        assert confirm(_finding()) is True
    finally:
        server.shutdown()


def test_oracle_shows_not_paid_confirms_false() -> None:
    _Oracle.paid = set()  # the forged order never flipped to paid
    server, base = _server()
    try:
        prober = HttpProber(EgressPolicy.for_run(target_hosts=["127.0.0.1"]))
        confirm = _settlement_confirmer_for(prober, f"{base}/orders/{{order_id}}")
        assert confirm(_finding()) is False  # -> NOT_REPRODUCED, never "vulnerability absent"
    finally:
        server.shutdown()


def test_no_oracle_url_is_inconclusive() -> None:
    prober = HttpProber(EgressPolicy.for_run(target_hosts=["127.0.0.1"]))
    confirm = _settlement_confirmer_for(prober, None)
    assert confirm(_finding()) is None  # no read-back -> INCONCLUSIVE, never VERIFIED


def test_out_of_scope_oracle_is_inconclusive() -> None:
    # An out-of-scope oracle URL is blocked by egress -> unconfirmable -> None.
    prober = HttpProber(EgressPolicy.for_run(target_hosts=["127.0.0.1"]))
    confirm = _settlement_confirmer_for(prober, "http://evil.example/orders/{order_id}")
    assert confirm(_finding()) is None
