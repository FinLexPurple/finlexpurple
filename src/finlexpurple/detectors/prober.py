"""The HTTP prober detectors use to probe in-scope endpoints (Phase 10).

Detectors are pure signal logic; they do not open sockets themselves. They call
a :class:`Prober`, which every request routes through the default-deny egress
policy (Phase 7, §15), an optional per-target request kill-ceiling and rate
limiter (§28 #4), before sending. Injecting the prober keeps each detector
deterministic and testable (a fake prober in unit tests, a real one against a
local vulnerable app in the integration test).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

import httpx

from finlexpurple.security.budget import RateLimiter, RequestBudget
from finlexpurple.security.egress_policy import EgressPolicy

_MAX_BODY_BYTES = 1024 * 1024


@dataclass(frozen=True)
class ProbeResponse:
    """A detector's view of a probe response: status, headers (lowercased), body text."""

    status_code: int
    headers: dict[str, str]
    text: str


class Prober(Protocol):
    """Sends one probe request and returns a :class:`ProbeResponse`."""

    def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        ...


class HttpProber:
    """A scope-safe prober: egress-checked, budget-capped, rate-limited HTTP.

    Every request is checked against the egress allow-list first (an
    out-of-scope URL raises before any socket opens), then charged to the
    per-target kill-ceiling and paced by the rate limiter if provided.
    """

    def __init__(
        self,
        egress: EgressPolicy,
        *,
        rate_limiter: RateLimiter | None = None,
        budget: RequestBudget | None = None,
        timeout: float = 10.0,
    ) -> None:
        self._egress = egress
        self._rate = rate_limiter
        self._budget = budget
        self._timeout = timeout

    def request(
        self,
        method: str,
        url: str,
        *,
        params: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
    ) -> ProbeResponse:
        self._egress.check_url(url)  # default-deny: out-of-scope raises before sending
        if self._budget is not None:
            self._budget.charge()
        if self._rate is not None:
            self._rate.acquire()
        with httpx.Client(follow_redirects=False, trust_env=False, timeout=self._timeout) as client:
            response = client.request(method.upper(), url, params=params, headers=headers)
            body = response.text[:_MAX_BODY_BYTES]
            lowered = {key.lower(): value for key, value in response.headers.items()}
            return ProbeResponse(status_code=response.status_code, headers=lowered, text=body)
