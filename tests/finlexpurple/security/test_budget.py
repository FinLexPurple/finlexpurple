"""Phase 7: request budget / kill-ceiling and rate limiter (decisions.md §28 item 4)."""

from __future__ import annotations

import pytest

from finlexpurple.security.budget import (
    RateLimiter,
    RequestBudget,
    RequestBudgetExceededError,
)


def test_budget_allows_up_to_ceiling_then_halts() -> None:
    budget = RequestBudget(max_requests=3)
    budget.charge()
    budget.charge()
    budget.charge()
    assert budget.used == 3
    assert budget.remaining == 0
    with pytest.raises(RequestBudgetExceededError, match="budget of 3"):
        budget.charge()


def test_budget_rejects_non_positive_ceiling() -> None:
    with pytest.raises(ValueError):
        RequestBudget(0)


def test_rate_limiter_waits_the_remaining_interval() -> None:
    clock = {"t": 100.0}
    slept: list[float] = []
    limiter = RateLimiter(
        min_interval_seconds=0.5,
        monotonic_fn=lambda: clock["t"],
        sleep_fn=slept.append,
    )
    # First acquire never waits.
    assert limiter.acquire() == 0.0
    assert slept == []
    # 0.2s later a 0.5s interval means waiting the remaining 0.3s.
    clock["t"] = 100.2
    waited = limiter.acquire()
    assert waited == pytest.approx(0.3)
    assert slept == [pytest.approx(0.3)]


def test_rate_limiter_does_not_wait_when_interval_already_elapsed() -> None:
    clock = {"t": 0.0}
    slept: list[float] = []
    limiter = RateLimiter(0.5, monotonic_fn=lambda: clock["t"], sleep_fn=slept.append)
    limiter.acquire()
    clock["t"] = 10.0  # well past the interval
    assert limiter.acquire() == 0.0
    assert slept == []
