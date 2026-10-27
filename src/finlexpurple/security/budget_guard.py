"""Default-on dollar spend cap for model usage (Phase 20; decisions.md §15).

Phase 6 gave the run default-on iteration/tool-call caps and Phase 7 a per-target
request kill-ceiling (``security/budget.py``). This module finalizes the third
default-on control §15 calls for: a **dollar spend cap**. Every model call the
orchestrator makes is metered against a running USD total, and once the cap is
reached the next call is refused so the run halts at a safe point — cleanly and
resumably — rather than spending without bound.

Design choices that keep the cap honest:

* **No bypass.** The only way the planner reaches a provider is through
  :class:`MeteredProvider`, which charges the guard on every ``complete`` call.
  There is no un-metered path to a paid API in the orchestration loop.
* **Erring high is the safe direction.** An unknown model is priced at a
  conservative upper bound rather than free, and a provider that does not report
  token usage is charged a conservative per-call estimate, so a cap can never be
  silently defeated by a model we have no price for.
* **Cost, not a crash.** Hitting the cap raises :class:`SpendBudgetExceededError`,
  which is deliberately *not* a :class:`~finlexpurple.providers.base.ProviderError`
  — the planner swallows provider errors and falls back to deterministic
  ordering, but a spend-cap stop must propagate to the engine, which records it
  as a stop reason and persists the state for ``resume``.

The prices below are published **list** prices in USD per one million tokens,
recorded as a pricing review for this release. They are reference figures and
must be re-checked each release; the cap's correctness does not depend on them
being exact, only on their being non-trivial upper bounds on real cost.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass

from finlexpurple.providers.base import LLMProvider, LLMResponse, Message, SchemaT

logger = logging.getLogger(__name__)

# Assumed token counts when a provider does not report usage, so a call still
# costs something and cannot slip past the cap. Deliberately generous.
_ASSUMED_INPUT_TOKENS = 4000
_ASSUMED_OUTPUT_TOKENS = 1000


@dataclass(frozen=True)
class ModelPrice:
    """List price in USD per one million input / output tokens."""

    input_per_million: float
    output_per_million: float

    def cost(self, input_tokens: int, output_tokens: int) -> float:
        return (
            input_tokens / 1_000_000 * self.input_per_million
            + output_tokens / 1_000_000 * self.output_per_million
        )


# Locally-run models (ollama and friends) have no per-token dollar cost.
_FREE = ModelPrice(0.0, 0.0)

# Conservative upper bound for a model we have no explicit price for: priced at
# the most expensive tier so an unknown model never understates spend.
FALLBACK_PRICE = ModelPrice(15.0, 75.0)

# Ordered (substring, price) table — first case-insensitive match on the model
# name wins, so more specific families are listed before their generic family.
# USD per 1M tokens, list prices recorded for this release's pricing review.
_PRICE_TABLE: tuple[tuple[str, ModelPrice], ...] = (
    # Local / self-hosted: no dollar cost.
    ("ollama", _FREE),
    ("llama", _FREE),
    ("mistral", _FREE),
    ("mixtral", _FREE),
    ("qwen", _FREE),
    ("gemma", _FREE),
    ("phi", _FREE),
    # Anthropic Claude families (opus > haiku > sonnet-class default).
    ("opus", ModelPrice(15.0, 75.0)),
    ("haiku", ModelPrice(0.80, 4.0)),
    ("sonnet", ModelPrice(3.0, 15.0)),
    ("claude", ModelPrice(3.0, 15.0)),
    # OpenAI / OpenRouter GPT families.
    ("gpt", ModelPrice(2.50, 10.0)),
    ("openai/", ModelPrice(2.50, 10.0)),
    # Google Gemini (flash tier is far cheaper than pro).
    ("flash", ModelPrice(0.075, 0.30)),
    ("gemini", ModelPrice(1.25, 5.0)),
)


def price_for(model: str) -> ModelPrice:
    """Return the per-token price for ``model`` (conservative fallback if unknown)."""

    name = (model or "").strip().lower()
    for marker, price in _PRICE_TABLE:
        if marker in name:
            return price
    logger.debug("No explicit price for model %r; using conservative fallback.", model)
    return FALLBACK_PRICE


def estimate_cost(response: LLMResponse) -> float:
    """Estimate the USD cost of one completed model response.

    Uses the reported token usage when present; otherwise charges a conservative
    assumed token count so an unmetered provider cannot slip past the cap.
    """

    price = price_for(response.model)
    usage = response.usage
    if usage is not None and (usage.input_tokens is not None or usage.output_tokens is not None):
        input_tokens = usage.input_tokens or 0
        output_tokens = usage.output_tokens or 0
    else:
        input_tokens, output_tokens = _ASSUMED_INPUT_TOKENS, _ASSUMED_OUTPUT_TOKENS
    return price.cost(input_tokens, output_tokens)


class SpendBudgetExceededError(RuntimeError):
    """The dollar spend cap was reached; no further paid model calls are allowed.

    Intentionally **not** a ``ProviderError`` so it propagates past the planner's
    provider-error fallback up to the engine, which stops the run resumably.
    """


class BudgetGuard:
    """A default-on cumulative USD cap on model spend for one run.

    ``check`` refuses the next call once the cap has been reached; ``record``
    adds the cost of a completed response. The guard is seeded from persisted
    state on resume so the cap spans the whole run, not just one segment.
    ``max_spend_usd`` must be positive — the cap is always a real number (§15),
    not optional; a user who wants a looser cap raises the number.
    """

    def __init__(self, max_spend_usd: float, *, spent_usd: float = 0.0) -> None:
        if max_spend_usd <= 0:
            raise ValueError("max_spend_usd must be a positive number.")
        if spent_usd < 0:
            raise ValueError("spent_usd cannot be negative.")
        self.max_spend_usd = float(max_spend_usd)
        self._spent = float(spent_usd)

    def seed(self, spent_usd: float) -> None:
        """Set the running total to a value recovered from persisted state.

        Used once at run start so a resumed run continues from what earlier
        segments already spent instead of resetting the cap to zero.
        """

        if spent_usd < 0:
            raise ValueError("spent_usd cannot be negative.")
        self._spent = float(spent_usd)

    @property
    def spent(self) -> float:
        return self._spent

    @property
    def remaining(self) -> float:
        return self.max_spend_usd - self._spent

    def check(self) -> None:
        """Raise if the cap has already been reached, before any further spend."""

        if self._spent >= self.max_spend_usd:
            logger.warning(
                "Dollar spend cap reached ($%.4f of $%.2f); halting at a safe point.",
                self._spent,
                self.max_spend_usd,
            )
            raise SpendBudgetExceededError(
                f"Spend cap of ${self.max_spend_usd:.2f} reached "
                f"(spent ${self._spent:.4f})."
            )

    def record(self, response: LLMResponse) -> float:
        """Add the cost of ``response`` to the running total; return that cost."""

        cost = estimate_cost(response)
        self._spent += cost
        logger.debug(
            "Model call cost $%.4f (model=%s); run total $%.4f of $%.2f.",
            cost,
            response.model,
            self._spent,
            self.max_spend_usd,
        )
        return cost


class MeteredProvider(LLMProvider):
    """Wraps a provider so every ``complete`` call is charged to a :class:`BudgetGuard`.

    This is the single choke point between the orchestrator and any paid API: the
    guard is checked *before* the call (so a run already at the cap spends
    nothing more) and charged *after* it, giving a clean, resumable stop at the
    next call once the cap is crossed.
    """

    def __init__(self, inner: LLMProvider, guard: BudgetGuard) -> None:
        self._inner = inner
        self._guard = guard

    def complete(
        self,
        messages: list[Message],
        *,
        response_schema: type[SchemaT] | None = None,
    ) -> LLMResponse:
        self._guard.check()
        response = self._inner.complete(messages, response_schema=response_schema)
        self._guard.record(response)
        return response
