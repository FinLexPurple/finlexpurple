"""Phase 10: SSRF surface detector."""

from __future__ import annotations

from finlexpurple.detectors import ssrf
from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.recon.endpoint_catalog import Endpoint


def test_flags_url_like_parameter(prober_factory) -> None:
    ep = Endpoint(method="GET", url="https://t.invalid/fetch", parameters=("url",), content_type=None)
    findings = ssrf.detect(ep, prober_factory(lambda *a, **k: ProbeResponse(200, {}, "")))
    assert len(findings) == 1 and findings[0].vulnerability_class == "ssrf"


def test_non_url_param_is_not_flagged(prober_factory) -> None:
    ep = Endpoint(method="GET", url="https://t.invalid/x", parameters=("name",), content_type=None)
    assert ssrf.detect(ep, prober_factory(lambda *a, **k: ProbeResponse(200, {}, ""))) == []


def test_accepts_url_param() -> None:
    assert ssrf.accepts_url_param("callback") and ssrf.accepts_url_param("redirect_uri")
    assert not ssrf.accepts_url_param("name")
