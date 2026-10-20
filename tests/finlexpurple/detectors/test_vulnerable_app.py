"""Phase 10 §5a: the four MVP detectors against a deliberately vulnerable app."""

from __future__ import annotations

from finlexpurple.detectors import idor, sqli, ssrf, xss
from finlexpurple.detectors.prober import HttpProber
from finlexpurple.recon.endpoint_catalog import Endpoint
from finlexpurple.security.egress_policy import EgressPolicy


def _prober() -> HttpProber:
    return HttpProber(EgressPolicy.for_run(target_hosts=["127.0.0.1"]))


def test_sqli_detected_end_to_end(vulnerable_server: str) -> None:
    ep = Endpoint("GET", vulnerable_server + "/search", ("q",), "text/html")
    findings = sqli.detect(ep, _prober())
    assert len(findings) == 1 and findings[0].vulnerability_class == "sqli"


def test_xss_detected_end_to_end(vulnerable_server: str) -> None:
    ep = Endpoint("GET", vulnerable_server + "/greet", ("name",), "text/html")
    findings = xss.detect(ep, _prober())
    assert len(findings) == 1 and findings[0].vulnerability_class == "xss"


def test_idor_detected_end_to_end(vulnerable_server: str) -> None:
    ep = Endpoint("GET", vulnerable_server + "/item", ("id",), "text/plain")
    findings = idor.detect(ep, _prober())
    assert len(findings) == 1 and findings[0].vulnerability_class == "idor"


def test_ssrf_surface_detected_end_to_end(vulnerable_server: str) -> None:
    ep = Endpoint("GET", vulnerable_server + "/fetch", ("url",), "text/plain")
    findings = ssrf.detect(ep, _prober())
    assert len(findings) == 1 and findings[0].vulnerability_class == "ssrf"


def test_all_findings_start_reported(vulnerable_server: str) -> None:
    ep = Endpoint("GET", vulnerable_server + "/search", ("q",), "text/html")
    for finding in sqli.detect(ep, _prober()):
        assert finding.status.value == "reported" and finding.agent == "hunter"
