"""Unit 2: webhook_bypass active-capture (forged callback) + passive fallback."""

from __future__ import annotations

from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.detectors.schema import FindingStatus
from finlexpurple.finance.payment_tests import webhook_bypass
from finlexpurple.recon.endpoint_catalog import Endpoint

_WEBHOOK = Endpoint(method="POST", url="http://t/payment/webhook", parameters=(), content_type=None)
_PLAIN = Endpoint(method="GET", url="http://t/search", parameters=("q",), content_type=None)


class _Prober:
    def __init__(self, status: int) -> None:
        self._status = status
        self.sent: list[tuple] = []

    def request(self, method, url, *, params=None, headers=None, body=None) -> ProbeResponse:
        self.sent.append((method, url, headers or {}, body))
        return ProbeResponse(self._status, {}, "received")


def test_accepted_forgery_is_captured_as_replayable() -> None:
    prober = _Prober(200)
    findings = webhook_bypass.check([_WEBHOOK], agent="cashier", prober=prober)
    assert len(findings) == 1
    f = findings[0]
    assert f.vulnerability_class == "webhook_bypass" and f.method == "POST"
    assert f.status is FindingStatus.REPORTED  # capture never verifies
    assert f.body and webhook_bypass.FORGED_ORDER_ID in f.body  # re-sendable forged body
    assert f.headers.get("X-Signature") == "invalid-not-a-real-hmac"  # unsigned/invalid by design
    # The forged POST was actually sent with a body.
    assert prober.sent and prober.sent[0][0] == "POST" and prober.sent[0][3]


def test_rejected_forgery_yields_no_finding() -> None:
    # A server that validates signatures rejects the forgery -> nothing to capture.
    findings = webhook_bypass.check([_WEBHOOK], agent="cashier", prober=_Prober(403))
    assert findings == []


def test_passive_mode_flags_a_candidate() -> None:
    findings = webhook_bypass.check([_WEBHOOK], agent="cashier")  # no prober
    assert len(findings) == 1 and findings[0].payload.startswith("webhook_bypass:")
    assert findings[0].body is None  # passive candidate carries no forged request


def test_non_webhook_endpoint_is_ignored() -> None:
    assert webhook_bypass.check([_PLAIN], agent="cashier", prober=_Prober(200)) == []
    assert webhook_bypass.looks_like_webhook(_WEBHOOK) and not webhook_bypass.looks_like_webhook(_PLAIN)
