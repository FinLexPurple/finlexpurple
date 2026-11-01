"""Decision 1: the bounded front-door selector (permute/subset-only, safe fallback)."""

from __future__ import annotations

import pytest

from finlexpurple.providers.base import LLMProvider, LLMResponse, ProviderError
from finlexpurple.security.budget_guard import SpendBudgetExceededError
from finlexpurple.selector import selector as sel
from finlexpurple.selector.selector import Selection, _SelectedAgents

_ECOMMERCE = "GET /checkout\nstripe payment_intent js.stripe.com"  # baseline: [hunter, cashier]
_ENDPOINTS = [object(), object()]


class _FakeProvider(LLMProvider):
    """Returns a fixed structured selection, or raises a supplied error."""

    def __init__(self, *, names=None, error=None) -> None:
        self._names = names
        self._error = error
        self.calls = 0

    def complete(self, messages, response_schema=None):  # type: ignore[override]
        self.calls += 1
        if self._error is not None:
            raise self._error
        return LLMResponse(content="", model="fake", structured=_SelectedAgents(agent_names=self._names))


def test_no_provider_uses_deterministic_baseline() -> None:
    result = sel.select(_ECOMMERCE, _ENDPOINTS)
    assert result.agents == ["hunter", "cashier"]
    assert result.source == "deterministic"


def test_single_candidate_skips_the_model() -> None:
    provider = _FakeProvider(names=["hunter"])
    result = sel.select("GET /about\nServer: nginx", _ENDPOINTS, provider)  # baseline: [hunter]
    assert result.agents == ["hunter"]
    assert result.source == "deterministic"
    assert provider.calls == 0  # <2 candidates -> never troubles a model


def test_valid_llm_subset_is_accepted() -> None:
    provider = _FakeProvider(names=["cashier"])  # model prunes hunter
    result = sel.select(_ECOMMERCE, _ENDPOINTS, provider)
    assert result.agents == ["cashier"]
    assert result.source == "llm"
    assert provider.calls == 1


def test_invented_name_falls_back_to_deterministic() -> None:
    provider = _FakeProvider(names=["cashier", "totally_invented_agent"])
    result = sel.select(_ECOMMERCE, _ENDPOINTS, provider)
    assert result.agents == ["hunter", "cashier"]
    assert result.source == "deterministic"


def test_duplicate_names_fall_back() -> None:
    provider = _FakeProvider(names=["hunter", "hunter"])
    result = sel.select(_ECOMMERCE, _ENDPOINTS, provider)
    assert result.source == "deterministic"


def test_provider_error_falls_back() -> None:
    provider = _FakeProvider(error=ProviderError("boom"))
    result = sel.select(_ECOMMERCE, _ENDPOINTS, provider)
    assert result.agents == ["hunter", "cashier"]
    assert result.source == "deterministic"


def test_budget_exceeded_propagates_and_is_not_swallowed() -> None:
    # The spend cap must halt the run, so the selector does NOT catch this.
    provider = _FakeProvider(error=SpendBudgetExceededError("cap"))
    with pytest.raises(SpendBudgetExceededError):
        sel.select(_ECOMMERCE, _ENDPOINTS, provider)


def test_capability_gaps_are_reported_regardless() -> None:
    result = sel.select(_ECOMMERCE + "\nPOST /graphql", _ENDPOINTS)
    assert "graphql" in [g.technology for g in result.gaps]
    assert isinstance(result, Selection)
