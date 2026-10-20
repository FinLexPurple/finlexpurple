"""Phase 10: IDOR detector (conservative heuristic)."""

from __future__ import annotations

from finlexpurple.detectors import idor
from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.recon.endpoint_catalog import Endpoint

_EP = Endpoint(method="GET", url="https://t.invalid/item", parameters=("id",), content_type="text/plain")


def test_detects_differing_200_bodies_for_different_ids(prober_factory) -> None:
    prober = prober_factory(lambda m, u, p, h: ProbeResponse(200, {}, f"record {p.get('id')}"))
    findings = idor.detect(_EP, prober)
    assert len(findings) == 1 and findings[0].vulnerability_class == "idor"


def test_identical_bodies_are_not_flagged(prober_factory) -> None:
    prober = prober_factory(lambda m, u, p, h: ProbeResponse(200, {}, "same for everyone"))
    assert idor.detect(_EP, prober) == []


def test_non_id_param_is_skipped(prober_factory) -> None:
    ep = Endpoint(method="GET", url="https://t.invalid/x", parameters=("q",), content_type=None)
    prober = prober_factory(lambda m, u, p, h: ProbeResponse(200, {}, f"r {p}"))
    assert idor.detect(ep, prober) == []


def test_looks_like_id_param() -> None:
    assert idor.looks_like_id_param("id") and idor.looks_like_id_param("user_id")
    assert not idor.looks_like_id_param("query")
