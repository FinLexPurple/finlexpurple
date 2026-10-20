"""Phase 10: SQLi detector."""

from __future__ import annotations

from finlexpurple.detectors import sqli
from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.detectors.schema import FindingStatus
from finlexpurple.recon.endpoint_catalog import Endpoint

_EP = Endpoint(method="GET", url="https://t.invalid/search", parameters=("q",), content_type="text/html")


def test_detects_sql_error(prober_factory) -> None:
    prober = prober_factory(lambda m, u, p, h: ProbeResponse(500, {}, "You have an error in your SQL syntax"))
    findings = sqli.detect(_EP, prober)
    assert len(findings) == 1
    assert findings[0].vulnerability_class == "sqli"
    assert findings[0].status is FindingStatus.REPORTED


def test_clean_endpoint_has_no_finding(prober_factory) -> None:
    prober = prober_factory(lambda m, u, p, h: ProbeResponse(200, {}, "all good"))
    assert sqli.detect(_EP, prober) == []


def test_finding_id_is_deterministic(prober_factory) -> None:
    prober = prober_factory(lambda m, u, p, h: ProbeResponse(500, {}, "sql syntax error near"))
    assert sqli.detect(_EP, prober)[0].finding_id == sqli.detect(_EP, prober)[0].finding_id
