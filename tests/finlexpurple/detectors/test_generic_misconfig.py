"""Phase 10: generic security-misconfiguration detector."""

from __future__ import annotations

from finlexpurple.detectors import generic_misconfig
from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.recon.endpoint_catalog import Endpoint

_EP = Endpoint(method="GET", url="https://t.invalid/", parameters=(), content_type="text/html")


def test_flags_missing_headers_and_server_banner(prober_factory) -> None:
    prober = prober_factory(lambda m, u, p, h: ProbeResponse(200, {"server": "nginx/1.25.3"}, "ok"))
    findings = generic_misconfig.detect(_EP, prober)
    classes = [f.expected_signal for f in findings]
    assert any("missing security headers" in c for c in classes)
    assert any("server version banner" in c for c in classes)
    # Two findings on one endpoint carry distinct finding ids.
    assert findings[0].finding_id != findings[1].finding_id


def test_hardened_response_has_no_finding(prober_factory) -> None:
    hardened = {
        "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff",
        "x-frame-options": "DENY",
    }
    prober = prober_factory(lambda m, u, p, h: ProbeResponse(200, hardened, "ok"))
    assert generic_misconfig.detect(_EP, prober) == []
