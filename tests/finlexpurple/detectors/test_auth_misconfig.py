"""Phase 10: auth/session misconfiguration detector."""

from __future__ import annotations

from finlexpurple.detectors import auth_misconfig
from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.recon.endpoint_catalog import Endpoint

_EP = Endpoint(method="GET", url="https://t.invalid/login", parameters=(), content_type="text/html")


def test_flags_insecure_cookie(prober_factory) -> None:
    prober = prober_factory(lambda m, u, p, h: ProbeResponse(200, {"set-cookie": "session=abc; Path=/"}, "ok"))
    findings = auth_misconfig.detect(_EP, prober)
    assert len(findings) == 1 and findings[0].vulnerability_class == "auth_misconfig"
    assert "secure" in findings[0].expected_signal and "httponly" in findings[0].expected_signal


def test_secure_httponly_cookie_is_ok(prober_factory) -> None:
    prober = prober_factory(lambda m, u, p, h: ProbeResponse(200, {"set-cookie": "s=1; Secure; HttpOnly"}, "ok"))
    assert auth_misconfig.detect(_EP, prober) == []


def test_no_cookie_no_finding(prober_factory) -> None:
    assert auth_misconfig.detect(_EP, prober_factory(lambda m, u, p, h: ProbeResponse(200, {}, "ok"))) == []
