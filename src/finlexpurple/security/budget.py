"""Per-target request budget / kill-ceiling and rate limiter (Phase 7; decisions.md §28 item 4).

Two complementary controls that bound the traffic a scan sends at a target:

* :class:`RateLimiter` paces requests (a minimum interval between them) — the
  polite, normal-operation control, usable by detection/exploitation modules
  as well as the crawler.
* :class:`RequestBudget` is the **hard kill-ceiling**: a maximum total number of
  requests per target that holds *even if rate limiting fails or is bypassed*.
  When it is hit the run cannot send another request — ``charge`` raises — so a
  bug or a misbehaving module can never flood a target without bound.

Both are deliberately simple and deterministic; the clock/sleep are injectable
so the rate limiter is testable without real time passing. This formalizes the
same default-on-caps idea as Phase 6's iteration limits (decisions.md §15); the
dollar spend cap is finalized separately in Phase 20.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from time import monotonic
from time import sleep as _sleep

logger = logging.getLogger(__name__)


class RequestBudgetExceededError(RuntimeError):
    """The per-target request kill-ceiling was reached; no further requests allowed."""


class RequestBudget:
    """A hard ceiling on total requests to a target.

    ``charge`` records one request and raises :class:`RequestBudgetExceededError`
    once the ceiling is reached, so the ceiling holds regardless of whether any
    rate limiter ran. ``max_requests`` must be positive.
    """

    def __init__(self, max_requests: int) -> None:
        if max_requests < 1:
            raise ValueError("max_requests must be a positive integer.")
        self.max_requests = max_requests
        self._used = 0

    @property
    def used(self) -> int:
        return self._used

    @property
    def remaining(self) -> int:
        return self.max_requests - self._used

    def charge(self) -> None:
        """Record one request; raise once the ceiling would be exceeded."""

        if self._used >= self.max_requests:
            logger.warning(
                "Request budget kill-ceiling reached (%d requests); halting.",
                self.max_requests,
            )
            raise RequestBudgetExceededError(
                f"Per-target request budget of {self.max_requests} reached."
            )
        self._used += 1


class RateLimiter:
    """Enforces a minimum interval between successive requests.

    ``acquire`` blocks (via the injected ``sleep``) only as long as needed to
    keep calls at least ``min_interval_seconds`` apart. The clock and sleep are
    injectable so tests need no real delay.
    """

    def __init__(
        self,
        min_interval_seconds: float,
        *,
        monotonic_fn: Callable[[], float] = monotonic,
        sleep_fn: Callable[[float], None] = _sleep,
    ) -> None:
        if min_interval_seconds < 0:
            raise ValueError("min_interval_seconds cannot be negative.")
        self.min_interval_seconds = min_interval_seconds
        self._monotonic = monotonic_fn
        self._sleep = sleep_fn
        self._last: float | None = None

    def acquire(self) -> float:
        """Wait if needed to honor the interval; return the seconds actually waited."""

        now = self._monotonic()
        waited = 0.0
        if self._last is not None and self.min_interval_seconds:
            elapsed = now - self._last
            remaining = self.min_interval_seconds - elapsed
            if remaining > 0:
                self._sleep(remaining)
                waited = remaining
                now = now + remaining
        self._last = now
        return waited
