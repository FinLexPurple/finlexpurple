"""Phase 10: cache-poisoning candidate detector."""

from __future__ import annotations

from finlexpurple.detectors import cache_poisoning
from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.recon.endpoint_catalog import Endpoint

_EP = Endpoint(method="GET", url="https://t.invalid/", parameters=(), content_type="text/html")


def test_detects_reflected_unkeyed_header(prober_factory) -> None:
    prober = prober_factory(lambda m, u, p, h: ProbeResponse(200, {}, f"host={h.get('X-Forwarded-Host', '')}"))
    findings = cache_poisoning.detect(_EP, prober)
    assert len(findings) == 1 and findings[0].vulnerability_class == "cache_poisoning"


def test_no_reflection_no_finding(prober_factory) -> None:
    prober = prober_factory(lambda m, u, p, h: ProbeResponse(200, {}, "static page"))
    assert cache_poisoning.detect(_EP, prober) == []
