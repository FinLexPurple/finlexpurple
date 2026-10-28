"""Task 1: price_tampering active capture (injected prober) + passive fallback.

Active mode sends one tampered request per price-like parameter and captures the
real request/response on reflection; passive mode (no prober) keeps today's
name-only prose candidate so ``run_all`` / the scan path is unchanged. Nothing
here promotes a finding past ``reported``.
"""

from __future__ import annotations

from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.detectors.schema import FindingStatus
from finlexpurple.finance.payment_tests import price_tampering
from finlexpurple.recon.endpoint_catalog import Endpoint

_EP = Endpoint(method="POST", url="http://t/checkout", parameters=("price", "coupon"), content_type=None)


class _FakeProber:
    """A deterministic prober: returns whatever a responder callable produces."""

    def __init__(self, responder):
        self._responder = responder
        self.calls: list[tuple] = []

    def request(self, method, url, *, params=None, headers=None):
        params = params or {}
        headers = headers or {}
        self.calls.append((method, url, params, headers))
        return self._responder(method, url, params, headers)


def test_active_capture_records_reexecutable_evidence() -> None:
    # A checkout that reflects whatever price it is given -> the tamper "succeeds".
    prober = _FakeProber(lambda m, u, p, h: ProbeResponse(200, {}, f"total={p.get('price', '')}"))
    findings = price_tampering.check([_EP], agent="cashier", prober=prober)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.payload == "price=0.01"              # concrete param=value, replayable
    assert finding.response_snapshot == "total=0.01"    # server's response captured
    assert finding.status is FindingStatus.REPORTED     # captured, not verified
    # Exactly one in-scope probe went out, carrying the tampered value.
    assert prober.calls == [("POST", "http://t/checkout", {"price": "0.01"}, {})]


def test_active_no_reflection_yields_no_finding() -> None:
    # A checkout that ignores the tampered price (rejects it) -> no evidence, no finding.
    prober = _FakeProber(lambda m, u, p, h: ProbeResponse(200, {}, "total=49.99"))
    assert price_tampering.check([_EP], agent="cashier", prober=prober) == []


def test_passive_fallback_unchanged_without_prober() -> None:
    findings = price_tampering.check([_EP], agent="cashier")
    assert len(findings) == 1
    assert findings[0].payload == (
        "price_tampering:price-like parameter(s) ['price'] may be client-controlled"
    )
    assert findings[0].response_snapshot is None


def test_finding_id_deterministic_in_active_mode() -> None:
    def responder(m, u, p, h):
        return ProbeResponse(200, {}, "total=0.01")

    first = price_tampering.check([_EP], agent="cashier", prober=_FakeProber(responder))[0]
    second = price_tampering.check([_EP], agent="cashier", prober=_FakeProber(responder))[0]
    assert first.finding_id == second.finding_id
