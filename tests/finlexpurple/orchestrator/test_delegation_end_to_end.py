"""Unit 4: the full delegation flow, end to end (the integration proof).

One run against a real in-process, multi-surface deliberately-vulnerable dummy
(checkout + forgeable webhook + an unsupported graphql surface) proves the whole
chain holds together:

* the front-door selector picks exactly ``[hunter, cashier]`` and SKIPS every
  irrelevant specialist (no teller/vault/ledger/...);
* a CapabilityGap is surfaced for the unsupported graphql surface (report-only;
  no specialist is ever generated at runtime);
* both financial replay specialists — price_tampering AND webhook_bypass — reach
  VERIFIED behind the approving gate, via the in-scope read-backs;
* the written report records the precise statuses; and
* each VERIFIED finding's signed evidence bundle verifies offline (hash).
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar
from urllib.parse import parse_qs, urlsplit

from finlexpurple.detectors.prober import HttpProber
from finlexpurple.detectors.schema import Finding, FindingStatus
from finlexpurple.evidence.verify import verify_bundle
from finlexpurple.gates.approval_gate import ApprovalGate
from finlexpurple.orchestrator.executor import WebDetector
from finlexpurple.recon.endpoint_catalog import Endpoint
from finlexpurple.reporting.output_layout import write_report
from finlexpurple.security.egress_policy import EgressPolicy
from finlexpurple.selector import selector
from finlexpurple.verifier.read_back import settlement_confirmer_for as _settlement_confirmer_for

_CHECKOUT = {"method": "GET", "path": "/checkout", "parameter_names": ["price"], "content_type": None}
_WEBHOOK = {"method": "POST", "path": "/payment/webhook", "parameter_names": [], "content_type": None}
_GRAPHQL = {"method": "POST", "path": "/graphql", "parameter_names": [], "content_type": None}


class _MultiSurfaceVulnApp(BaseHTTPRequestHandler):
    """Vulnerable: trusts a client-sent price and accepts unsigned 'paid' callbacks."""

    persisted_price = "49.99"
    orders: ClassVar[dict[str, str]] = {}

    def log_message(self, *a: object) -> None:
        return

    def _send(self, body: str) -> None:
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        parts = urlsplit(self.path)
        query = {k: v[0] for k, v in parse_qs(parts.query).items()}
        if parts.path == "/checkout" and "price" in query:
            type(self).persisted_price = query["price"]  # trusts the client price (vuln)
            self._send(f"total={query['price']}")
        elif parts.path == "/checkout":
            self._send(f"receipt total={type(self).persisted_price}")
        elif parts.path.startswith("/orders/"):  # a SEPARATE per-order status oracle
            order_id = parts.path.rsplit("/", 1)[-1]
            status = type(self).orders.get(order_id, "pending")
            self._send(f'{{"order_id": "{order_id}", "status": "{status}"}}')
        else:
            self._send("ok")

    def do_POST(self) -> None:
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or 0)).decode()
        if urlsplit(self.path).path == "/payment/webhook":
            # Vulnerable: accepts the unsigned callback and flips the order to paid.
            data = json.loads(raw) if raw else {}
            if data.get("status") == "paid":
                type(self).orders[data.get("order_id")] = "paid"
            self._send('{"received": true}')
        else:
            self._send("ok")


def test_full_delegation_flow_end_to_end(tmp_path) -> None:
    _MultiSurfaceVulnApp.persisted_price = "49.99"
    _MultiSurfaceVulnApp.orders = {}
    server = ThreadingHTTPServer(("127.0.0.1", 0), _MultiSurfaceVulnApp)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        base = f"http://127.0.0.1:{server.server_address[1]}"
        endpoints = [
            Endpoint("GET", f"{base}/checkout", ("price",), None),
            Endpoint("POST", f"{base}/payment/webhook", (), None),
            Endpoint("POST", f"{base}/graphql", (), None),
        ]
        corpus = "/checkout\nprice\n/payment/webhook\n/graphql"

        # 1) Selector picks exactly [hunter, cashier] and surfaces the graphql gap.
        selection = selector.select(corpus, endpoints, provider=None)
        assert selection.agents == ["hunter", "cashier"]
        assert not ({"teller", "vault", "ledger", "broker", "underwriter", "courier"} & set(selection.agents))
        assert any(gap.technology == "graphql" for gap in selection.gaps)
        run_financial = "cashier" in selection.agents

        # 2) Scan the surfaces with the real prober + an approving gate + in-scope read-backs.
        prober = HttpProber(EgressPolicy.for_run(target_hosts=["127.0.0.1"]))
        gate = ApprovalGate(True, interactive=True, confirm_fn=lambda _p: True)

        def charge(finding: Finding, value: str) -> bool | None:
            return value in prober.request("GET", finding.url).text

        # Settlement is confirmed from a SEPARATE order-status oracle (the real
        # CLI confirmer), not by re-reading the webhook endpoint.
        settle = _settlement_confirmer_for(prober, f"{base}/orders/{{order_id}}")

        sink: list[Finding] = []
        detector = WebDetector(
            origin=base, prober=prober, sink=sink, gate=gate,
            charge_confirmer=charge, settlement_confirmer=settle, run_financial=run_financial,
        )
        for record in (_CHECKOUT, _WEBHOOK, _GRAPHQL):
            detector.run(record)

        # 3) Both financial replay specialists reached VERIFIED.
        by_class = {f.vulnerability_class: f for f in sink}
        assert by_class["price_tampering"].status is FindingStatus.VERIFIED
        assert by_class["webhook_bypass"].status is FindingStatus.VERIFIED

        # 4) The written report records the precise statuses and signs the verified bundles.
        paths = write_report(sink, target=base, out_dir=tmp_path)
        report = json.loads(paths.report_json.read_text(encoding="utf-8"))
        assert report["summary"]["by_status"]["verified"] >= 2

        bundles = sorted(paths.evidence_dir.glob("*.bundle.json"))
        assert len(bundles) >= 2  # one per verified finding
        for bundle_path in bundles:
            result = verify_bundle(bundle_path.read_text(encoding="utf-8"))
            assert result.ok and result.hash_ok  # offline hash verification holds
    finally:
        server.shutdown()
