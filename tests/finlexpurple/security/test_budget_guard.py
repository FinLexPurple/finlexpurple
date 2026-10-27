"""Phase 20: the default-on dollar spend cap (decisions.md §15).

Covers pricing (known families, conservative fallback, missing-usage estimate),
the guard's check/record/seed semantics, the MeteredProvider choke point, and
the end-to-end acceptance item: a low MAX_SPEND_USD stops a run cleanly and
resumably, with spend carried across the resume boundary.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from finlexpurple.orchestrator import engine
from finlexpurple.orchestrator.planner import Planner
from finlexpurple.orchestrator.state import RunState
from finlexpurple.providers.base import (
    LLMProvider,
    LLMResponse,
    Message,
    ProviderError,
    SchemaT,
    Usage,
)
from finlexpurple.security.budget_guard import (
    FALLBACK_PRICE,
    BudgetGuard,
    MeteredProvider,
    SpendBudgetExceededError,
    estimate_cost,
    price_for,
)


def _response(model: str, inp: int | None, out: int | None) -> LLMResponse:
    usage = None if inp is None and out is None else Usage(input_tokens=inp, output_tokens=out)
    return LLMResponse(content="ok", model=model, usage=usage)


# ----- pricing -----

def test_known_families_are_priced_and_local_is_free() -> None:
    assert price_for("claude-sonnet-5-5").input_per_million == 3.0
    assert price_for("claude-opus-4-8").output_per_million == 75.0
    assert price_for("gpt-6.1-sol").input_per_million == 2.50
    assert price_for("gemini-3.8-flash").input_per_million == 0.075
    # Local / self-hosted models cost nothing.
    assert price_for("llama3.1:8b").input_per_million == 0.0
    assert price_for("qwen2.5").output_per_million == 0.0


def test_unknown_model_uses_conservative_fallback_not_free() -> None:
    # An unpriced model must never be treated as free, or the cap is defeated.
    assert price_for("some-brand-new-model-x") is FALLBACK_PRICE
    assert FALLBACK_PRICE.input_per_million > 0


def test_missing_usage_is_charged_a_nonzero_estimate() -> None:
    # A provider that reports no token usage must still cost something.
    cost = estimate_cost(_response("gpt-6.1-sol", None, None))
    assert cost > 0


def test_reported_usage_is_priced_exactly() -> None:
    # 1M input @ $3 + 1M output @ $15 = $18 for a sonnet-class model.
    cost = estimate_cost(_response("claude-sonnet-5-5", 1_000_000, 1_000_000))
    assert cost == pytest.approx(18.0)


# ----- guard semantics -----

def test_guard_rejects_nonpositive_cap() -> None:
    with pytest.raises(ValueError, match="positive"):
        BudgetGuard(0)
    with pytest.raises(ValueError, match="positive"):
        BudgetGuard(-1.0)


def test_check_passes_until_cap_then_refuses() -> None:
    guard = BudgetGuard(10.0)
    guard.check()  # nothing spent yet
    guard.record(_response("claude-sonnet-5-5", 1_000_000, 0))  # +$3
    guard.check()  # still under $10
    guard.record(_response("claude-opus-4-8", 0, 1_000_000))  # +$75, now over
    with pytest.raises(SpendBudgetExceededError, match="Spend cap"):
        guard.check()


def test_seed_restores_prior_spend() -> None:
    guard = BudgetGuard(10.0)
    guard.seed(9.5)
    assert guard.spent == 9.5
    assert guard.remaining == pytest.approx(0.5)


# ----- metered provider: the single choke point -----

class _StubProvider(LLMProvider):
    def __init__(self, response: LLMResponse) -> None:
        self._response = response
        self.calls = 0

    def complete(self, messages: list[Message], *, response_schema: type[SchemaT] | None = None) -> LLMResponse:
        self.calls += 1
        return self._response


def test_metered_provider_charges_every_call_then_blocks() -> None:
    inner = _StubProvider(_response("claude-opus-4-8", 0, 1_000_000))  # $75 per call
    guard = BudgetGuard(100.0)
    metered = MeteredProvider(inner, guard)
    metered.complete([Message(role="user", content="x")])  # $75
    assert inner.calls == 1
    # Second call's pre-check sees $75 < $100 so it runs, pushing total to $150.
    metered.complete([Message(role="user", content="x")])
    assert inner.calls == 2
    # Now over the cap: the next pre-check refuses before the inner provider runs.
    with pytest.raises(SpendBudgetExceededError):
        metered.complete([Message(role="user", content="x")])
    assert inner.calls == 2  # inner was NOT called again


def test_spend_cap_error_is_not_a_provider_error() -> None:
    # The planner swallows ProviderError; a spend-cap stop must NOT be swallowed.
    assert not issubclass(SpendBudgetExceededError, ProviderError)


# ----- acceptance: low cap stops the run cleanly and resumably -----

def _state_with_catalog(n: int) -> RunState:
    catalog = [
        {"method": "GET", "path": f"/p{i}", "parameter_names": ["q"], "content_type": None}
        for i in range(n)
    ]
    return RunState(
        run_id="hash1234-run",
        canonical_target="https://example.test",
        current_stage="plan",
        catalog=catalog,
    )


def test_low_spend_cap_stops_run_cleanly_and_resumably(tmp_path: Path) -> None:
    # A provider priced so one call exhausts a tiny cap. The planner needs >= 2
    # pending actions to call the provider at all.
    expensive = _response("claude-opus-4-8", 1_000_000, 1_000_000)  # ~$90 per call
    guard = BudgetGuard(1.0)  # $1 cap: one call blows it
    metered = MeteredProvider(_StubProvider(expensive), guard)
    planner = Planner(metered)

    state = _state_with_catalog(3)
    state_path = tmp_path / "run-state.json"

    final = engine.run(state, state_path, planner=planner, budget_guard=guard)

    # Stopped, not finished: a clear spend-cap reason, state persisted to disk.
    assert final.current_stage != "report"
    assert final.stop_reason is not None and "Spend cap" in final.stop_reason
    assert state_path.exists()
    assert final.spend_usd > 0

    # Resumable: reload the persisted state and confirm spend carried across.
    from finlexpurple.orchestrator.persistence import load_state

    reloaded = load_state(state_path)
    assert reloaded.spend_usd == pytest.approx(final.spend_usd)
    assert reloaded.current_stage == final.current_stage

    # Resuming with the same cap refuses immediately (already over) and does not
    # advance — the cap spans the whole run rather than resetting.
    resume_guard = BudgetGuard(1.0)
    resumed = engine.run(
        reloaded, state_path, planner=Planner(MeteredProvider(_StubProvider(expensive), resume_guard)),
        budget_guard=resume_guard,
    )
    assert resumed.current_stage != "report"
    assert resumed.stop_reason is not None and "Spend cap" in resumed.stop_reason
