"""Task 1: _common.tampered_finding captures a re-executable price-tamper request.

The passive ``candidate_finding`` helper the other six payment checks share must
stay unchanged (no regression); the new ``tampered_finding`` helper records the
concrete request + response evidence a later deterministic replay needs.
"""

from __future__ import annotations

from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.detectors.schema import FindingStatus, Severity
from finlexpurple.finance.payment_tests import _common
from finlexpurple.recon.endpoint_catalog import Endpoint

_EP = Endpoint(method="POST", url="http://t/checkout", parameters=("price",), content_type=None)


def test_tampered_finding_captures_concrete_request() -> None:
    response = ProbeResponse(200, {"content-type": "text/html"}, "order total: 0.01 confirmed")
    finding = _common.tampered_finding(
        _EP, param="price", tampered_value="0.01", response=response,
        request_headers={}, severity=Severity.HIGH, agent="cashier",
    )
    assert finding.vulnerability_class == "price_tampering"
    assert finding.payload == "price=0.01"               # concrete param=value, not a prose label
    assert finding.response_snapshot == "order total: 0.01 confirmed"
    assert finding.body is None                          # query-param tamper (Task 1 scope)
    assert finding.headers == {}                         # headers as sent (none, here)
    assert "0.01" in finding.expected_signal             # code-checkable criterion names the value
    assert finding.status is FindingStatus.REPORTED      # capture never verifies
    assert finding.agent == "cashier"


def test_tampered_finding_truncates_large_snapshot() -> None:
    finding = _common.tampered_finding(
        _EP, param="price", tampered_value="0.01",
        response=ProbeResponse(200, {}, "x" * 5000), request_headers={},
        severity=Severity.HIGH, agent="cashier",
    )
    assert finding.response_snapshot is not None
    assert len(finding.response_snapshot) == 2000        # matches the sqli[:2000] convention


def test_candidate_finding_unchanged() -> None:
    # The passive helper the other six checks share is byte-for-byte unchanged:
    # still a prose payload and no captured response.
    finding = _common.candidate_finding(
        _EP, vclass="price_tampering", reason="r", severity=Severity.HIGH, agent="cashier",
    )
    assert finding.payload == "price_tampering:r"
    assert finding.response_snapshot is None
    assert finding.status is FindingStatus.REPORTED
