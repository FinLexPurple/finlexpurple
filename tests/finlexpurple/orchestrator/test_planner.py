"""Combined fix Parts B/C: planner deterministic by default + a clear failure warning.

B: with no provider the planner makes zero model calls and returns the deterministic
order; with a provider it reorders (same action set, order only). C: when a provider
call fails, it logs a clear "using deterministic order" warning and still falls back.
"""

from __future__ import annotations

import logging

from finlexpurple.orchestrator.planner import Planner, _PriorityOrder
from finlexpurple.providers.base import LLMResponse, Message, ProviderError

_CATALOG = [
    {"path": "/a", "parameter_names": [], "content_type": None},
    {"path": "/b", "parameter_names": [], "content_type": None},
]


class _RecordingProvider:
    def __init__(self) -> None:
        self.calls = 0

    def complete(self, messages: list[Message], *, response_schema=None) -> LLMResponse:
        self.calls += 1
        return LLMResponse(
            content="", model="fake",
            structured=_PriorityOrder(action_ids=["stub-0001", "stub-0000"]),  # reverse order
        )


class _FailingProvider:
    def complete(self, messages: list[Message], *, response_schema=None) -> LLMResponse:
        raise ProviderError("401 Unauthorized (invalid API key)")


def test_default_planner_makes_no_model_call() -> None:
    order = [a["action_id"] for a in Planner().plan(_CATALOG, set())]
    assert order == ["stub-0000", "stub-0001"]  # deterministic, zero model calls


def test_provider_reorders_same_action_set() -> None:
    provider = _RecordingProvider()
    order = [a["action_id"] for a in Planner(provider).plan(_CATALOG, set())]
    assert provider.calls == 1
    assert order == ["stub-0001", "stub-0000"]  # reordered (order only) ...
    assert set(order) == {"stub-0000", "stub-0001"}  # ... same action set


def test_provider_failure_warns_and_falls_back(caplog) -> None:
    with caplog.at_level(logging.WARNING, logger="finlexpurple.orchestrator.planner"):
        order = [a["action_id"] for a in Planner(_FailingProvider()).plan(_CATALOG, set())]
    assert order == ["stub-0000", "stub-0001"]  # deterministic fallback
    assert any("using deterministic order" in r.getMessage() for r in caplog.records)
