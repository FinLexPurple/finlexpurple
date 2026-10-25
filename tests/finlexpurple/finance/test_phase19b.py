"""Phase 19b: the remaining five financial agents register and run read-only."""

from __future__ import annotations

from finlexpurple.agents import invoker
from finlexpurple.agents.registry import AgentRequest, get_agent, registered_agents
from finlexpurple.detectors.schema import Finding, FindingStatus
from finlexpurple.recon.endpoint_catalog import Endpoint

_19B = ("ledger", "broker", "vault", "underwriter", "courier")


def _payment_endpoints(_url: str) -> list[Endpoint]:
    return [
        Endpoint(method="POST", url="http://t/checkout", parameters=("price",), content_type=None),
        Endpoint(method="POST", url="http://t/refund", parameters=(), content_type=None),
    ]


def test_all_eight_financial_agents_registered() -> None:
    financial = {a.name for a in registered_agents() if a.family == "financial"}
    assert financial == {"compass", "cashier", "teller", *_19B}  # the full §14 roster


def test_each_19b_agent_runs_read_only_and_reports_schema_findings() -> None:
    for name in _19B:
        result = invoker.invoke(
            get_agent(name), AgentRequest(target="http://t/", recon=_payment_endpoints)
        )
        assert result.findings and all(isinstance(f, Finding) for f in result.findings)
        assert all(f.status is FindingStatus.REPORTED for f in result.findings)  # never auto-exploited
        assert all(f.agent == name for f in result.findings)


def test_vault_advertises_the_hard_gate() -> None:
    result = invoker.invoke(
        get_agent("vault"), AgentRequest(target="http://t/", recon=_payment_endpoints)
    )
    assert "hard-gated" in result.summary and "never auto-run" in result.summary


def test_phases_are_labeled() -> None:
    assert get_agent("vault").phase == "Phase 19b"
    assert get_agent("ledger").phase == "Phase 19b"
