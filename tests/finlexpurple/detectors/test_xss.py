"""Phase 10: reflected-XSS detector."""

from __future__ import annotations

from finlexpurple.detectors import xss
from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.recon.endpoint_catalog import Endpoint

_EP = Endpoint(method="GET", url="https://t.invalid/greet", parameters=("name",), content_type="text/html")


def _reflect(m, u, params, h) -> ProbeResponse:
    return ProbeResponse(200, {"content-type": "text/html"}, f"<h1>{params.get('name', '')}</h1>")


def test_detects_unescaped_reflection(prober_factory) -> None:
    findings = xss.detect(_EP, prober_factory(_reflect))
    assert len(findings) == 1 and findings[0].vulnerability_class == "xss"


def test_escaped_or_nonhtml_is_not_flagged(prober_factory) -> None:
    escaped = prober_factory(lambda m, u, p, h: ProbeResponse(200, {"content-type": "text/html"}, "&lt;flpxss-name&gt;"))
    assert xss.detect(_EP, escaped) == []
    plain = prober_factory(lambda m, u, p, h: ProbeResponse(200, {"content-type": "application/json"}, p.get("name", "")))
    assert xss.detect(_EP, plain) == []


def test_finding_id_is_deterministic(prober_factory) -> None:
    assert xss.detect(_EP, prober_factory(_reflect))[0].finding_id == xss.detect(_EP, prober_factory(_reflect))[0].finding_id
