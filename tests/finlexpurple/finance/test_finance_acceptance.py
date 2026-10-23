"""Phase 19a §5a acceptance: triage, registration, and the Teller hard gate."""

from __future__ import annotations

from finlexpurple.agents import invoker
from finlexpurple.agents.registry import AgentRequest, get_agent, registered_agents
from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.detectors.schema import Finding, FindingStatus
from finlexpurple.recon.endpoint_catalog import Endpoint


class _Prober:
    """Returns a fixed body (the fingerprint corpus) for any request."""

    def __init__(self, body: str) -> None:
        self._body = body

    def request(self, method, url, *, params=None, headers=None):
        return ProbeResponse(status_code=200, headers={}, text=self._body)


def _payment_endpoints(_url: str) -> list[Endpoint]:
    return [
        Endpoint(method="POST", url="http://t/checkout", parameters=("price",), content_type=None),
        Endpoint(method="GET", url="http://t/order", parameters=("order_id",), content_type=None),
    ]


def test_all_three_financial_agents_are_registered() -> None:
    financial = {a.name for a in registered_agents() if a.family == "financial"}
    assert {"compass", "cashier", "teller"} <= financial


def test_compass_recommends_the_right_specialist() -> None:
    cases = {
        "page with js.stripe.com payment_intent": "cashier",
        "online-banking account/transfer netbanking": "teller",
        "billing plans recurring chargebee": "ledger",
    }
    for corpus, expected in cases.items():
        result = invoker.invoke(
            get_agent("compass"),
            AgentRequest(target="http://t/", prober=_Prober(corpus), recon=lambda _u: []),
        )
        assert f"recommended specialist: {expected}" in result.summary


def test_cashier_produces_reported_schema_findings() -> None:
    result = invoker.invoke(
        get_agent("cashier"),
        AgentRequest(target="http://t/", prober=_Prober(""), recon=_payment_endpoints),
    )
    assert result.findings and all(isinstance(f, Finding) for f in result.findings)
    assert all(f.status is FindingStatus.REPORTED for f in result.findings)  # never auto-exploited


def test_teller_runs_read_only_and_advertises_the_hard_gate() -> None:
    result = invoker.invoke(
        get_agent("teller"),
        AgentRequest(target="http://t/", prober=_Prober(""), recon=_payment_endpoints),
    )
    assert all(f.status is FindingStatus.REPORTED for f in result.findings)  # read-only
    assert "hard-gated" in result.summary and "never auto-run" in result.summary
