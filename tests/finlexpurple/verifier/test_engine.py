"""Phase 11: the verification engine dispatch + status/log updates (fake collaborators)."""

from __future__ import annotations

from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.detectors.schema import Finding, FindingStatus
from finlexpurple.gates.approval_gate import ApprovalGate
from finlexpurple.verifier import engine


class _FakeProber:
    def __init__(self, responder) -> None:
        self._responder = responder

    def request(self, method, url, *, params=None, headers=None) -> ProbeResponse:
        return self._responder(params or {}, headers or {})


def _sqli() -> Finding:
    return Finding.new(vulnerability_class="sqli", method="GET", url="https://t.invalid/s", payload="q='")


def test_sqli_verified_when_error_reproduces() -> None:
    prober = _FakeProber(lambda p, h: ProbeResponse(500, {}, "sql syntax error near"))
    finding = engine.verify(_sqli(), prober=prober)
    assert finding.status is FindingStatus.VERIFIED
    assert "reproduced" in (finding.verification_log or "")


def test_sqli_reported_when_not_reproduced() -> None:
    prober = _FakeProber(lambda p, h: ProbeResponse(200, {}, "all good"))
    assert engine.verify(_sqli(), prober=prober).status is FindingStatus.REPORTED


def test_sqli_without_prober_stays_reported() -> None:
    finding = engine.verify(_sqli())
    assert finding.status is FindingStatus.REPORTED
    assert "requires a prober" in (finding.verification_log or "")


def test_idor_two_session_diff() -> None:
    same_body = _FakeProber(lambda p, h: ProbeResponse(200, {}, "secret record 1"))
    verified = engine.verify(
        Finding.new(vulnerability_class="idor", method="GET", url="https://t/i", payload="id=1|2"),
        prober=same_body,
        sessions=({"X-User": "owner"}, {"X-User": "other"}),
    )
    assert verified.status is FindingStatus.VERIFIED


def test_xss_uses_browser_runner_result() -> None:
    def xss_finding() -> Finding:
        return Finding.new(vulnerability_class="xss", method="GET", url="https://t/x", payload="name=<x>")

    assert engine.verify(xss_finding(), browser_runner=lambda u, m: True).status is FindingStatus.VERIFIED
    assert engine.verify(xss_finding(), browser_runner=lambda u, m: False).status is FindingStatus.REPORTED
    no_browser = engine.verify(xss_finding())
    assert no_browser.status is FindingStatus.REPORTED
    assert "headless-browser" in (no_browser.verification_log or "")


def _price_tampering() -> Finding:
    return Finding.new(
        vulnerability_class="price_tampering", method="GET",
        url="http://t/checkout", payload="price=0.01", agent="cashier",
    )


def test_price_tampering_verified_only_when_charged() -> None:
    prober = _FakeProber(lambda p, h: ProbeResponse(200, {}, f"total={p.get('price', '')}"))
    gate = ApprovalGate(True, interactive=True, confirm_fn=lambda _p: True)
    charged = engine.verify(_price_tampering(), prober=prober, gate=gate, charge_confirmer=lambda f, v: True)
    assert charged.status is FindingStatus.VERIFIED
    reflected = engine.verify(_price_tampering(), prober=prober, gate=gate, charge_confirmer=lambda f, v: False)
    assert reflected.status is FindingStatus.REPORTED


def test_price_tampering_without_gate_stays_reported() -> None:
    prober = _FakeProber(lambda p, h: ProbeResponse(200, {}, "total=0.01"))
    finding = engine.verify(_price_tampering(), prober=prober)
    assert finding.status is FindingStatus.REPORTED
    assert "approval gate" in (finding.verification_log or "")


def test_unknown_and_cache_classes_stay_reported() -> None:
    unknown = engine.verify(Finding.new(vulnerability_class="auth_misconfig", method="GET", url="u", payload="x"))
    assert unknown.status is FindingStatus.REPORTED and "no replay engine" in (unknown.verification_log or "")
    cache = engine.verify(Finding.new(vulnerability_class="cache_poisoning", method="GET", url="u", payload="x"))
    assert cache.status is FindingStatus.REPORTED
