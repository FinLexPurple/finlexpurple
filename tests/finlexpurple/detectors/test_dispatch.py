"""Phase 10: fingerprint/shape-driven dispatch."""

from __future__ import annotations

from finlexpurple.detectors import (
    auth_misconfig,
    dispatch,
    generic_misconfig,
    idor,
    sqli,
    ssrf,
    xss,
)
from finlexpurple.recon.endpoint_catalog import Endpoint


def test_parameterless_endpoint_skips_param_detectors() -> None:
    ep = Endpoint(method="GET", url="https://t.invalid/", parameters=(), content_type="text/html")
    chosen = dispatch.relevant_detectors(ep)
    assert sqli.detect not in chosen and xss.detect not in chosen
    # Response/header-based detectors always run.
    assert generic_misconfig.detect in chosen and auth_misconfig.detect in chosen


def test_id_and_url_params_add_idor_and_ssrf() -> None:
    ep = Endpoint(method="GET", url="https://t.invalid/x", parameters=("user_id", "callback"), content_type="text/html")
    chosen = dispatch.relevant_detectors(ep)
    assert sqli.detect in chosen and xss.detect in chosen
    assert idor.detect in chosen and ssrf.detect in chosen


def test_plain_param_gets_sqli_xss_but_not_idor_ssrf() -> None:
    ep = Endpoint(method="GET", url="https://t.invalid/x", parameters=("q",), content_type="text/html")
    chosen = dispatch.relevant_detectors(ep)
    assert sqli.detect in chosen and xss.detect in chosen
    assert idor.detect not in chosen and ssrf.detect not in chosen
