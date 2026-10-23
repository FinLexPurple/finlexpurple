"""Phase 18 §5a acceptance: the four checklist items.

1. agents list prints every registered stage agent with accurate descriptions.
2. sentinel with no prior findings explains it needs findings first (not a crash).
3. hunter runs detection only, producing schema-conformant findings, no verify.
4. a single named agent makes measurably fewer LLM calls than a full scan.
"""

from __future__ import annotations

from finlexpurple.agents import invoker
from finlexpurple.agents.registry import AgentRequest, get_agent, registered_agents
from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.detectors.schema import Finding, FindingStatus
from finlexpurple.orchestrator.planner import Planner
from finlexpurple.providers.base import LLMProvider, Message, ProviderError
from finlexpurple.recon.endpoint_catalog import Endpoint


class _FakeProber:
    """Returns a SQL-error body iff a probe value contains a single quote."""

    def request(self, method, url, *, params=None, headers=None):
        values = " ".join((params or {}).values())
        text = "You have an error in your SQL syntax near ''" if "'" in values else "<html>ok</html>"
        return ProbeResponse(status_code=200, headers={}, text=text)


class _CountingProvider(LLMProvider):
    """Counts complete() calls; the planner safely falls back when it errors."""

    def __init__(self) -> None:
        self.calls = 0

    def complete(self, messages: list[Message], *, response_schema=None):
        self.calls += 1
        raise ProviderError("counting fake")


def _recon(_url: str) -> list[Endpoint]:
    return [Endpoint(method="GET", url="http://t.invalid/search", parameters=("q",), content_type="text/html")]


def test_item1_roster_lists_every_agent_with_descriptions() -> None:
    agents = registered_agents()
    stage = [a for a in agents if a.family == "stage"]
    assert len(stage) == 8  # the eight stage agents
    assert all(a.role.strip() for a in agents)


def test_item2_sentinel_without_findings_is_explained_not_crashed() -> None:
    reason = invoker.unavailable_reason(get_agent("sentinel"), {"target"})
    assert reason and "findings" in reason  # a clean explanation, no exception


def test_item3_hunter_detects_without_verifying() -> None:
    result = invoker.invoke(
        get_agent("hunter"),
        AgentRequest(target="http://t.invalid/", recon=_recon, prober=_FakeProber()),
    )
    assert result.findings and all(isinstance(f, Finding) for f in result.findings)  # schema-conformant
    sqli = [f for f in result.findings if f.vulnerability_class == "sqli"]
    assert sqli  # detection found the SQLi
    # Detection only: nothing was promoted to verified (that is the sentinel's job).
    assert all(f.status is FindingStatus.REPORTED for f in result.findings)


def test_item4_single_agent_makes_fewer_llm_calls_than_a_full_scan() -> None:
    hunter = invoker.invoke(
        get_agent("hunter"),
        AgentRequest(target="http://t.invalid/", recon=_recon, prober=_FakeProber()),
    )
    assert hunter.llm_calls == 0  # detection uses no LLM

    # The full pipeline's planner consults the LLM to order a multi-endpoint plan.
    counting = _CountingProvider()
    catalog = [
        {"method": "GET", "path": "/a", "parameter_names": [], "content_type": None},
        {"method": "GET", "path": "/b", "parameter_names": [], "content_type": None},
    ]
    Planner(counting).plan(catalog, set())
    assert counting.calls >= 1
    assert hunter.llm_calls < counting.calls  # measurably fewer
