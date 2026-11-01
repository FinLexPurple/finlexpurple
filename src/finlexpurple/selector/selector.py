"""One bounded, permute/subset-only LLM pass over the registry (Decision 1).

This mirrors the boundary of :mod:`finlexpurple.orchestrator.planner`: a single
``provider.complete`` call with an ``extra="forbid"`` schema that may only return
a **subset-and-ordering of the fixed registry's selectable specialist names**. It
can never invent, add, or rename an agent. On a :class:`ProviderError` or any
non-conforming output it falls back to deterministic relevance selection
(:mod:`finlexpurple.selector.relevance`).

A ``SpendBudgetExceededError`` is deliberately **not** caught here: like the
planner, the selector lets it propagate so the Phase 15 spend cap halts the run
(see ``security/budget_guard.py`` — that error is intentionally not a
``ProviderError``). Catching it would weaken the cap, so we do not.

The selector only decides *what runs and in what order*. It never verifies a
finding, touches a gate, or sets a status — those invariants stay in
``verifier/`` and ``gates/``.
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field

from pydantic import BaseModel, ConfigDict

from finlexpurple.agents.registry import get_agent, registered_agents
from finlexpurple.finance import gateway_profiles
from finlexpurple.providers.base import LLMProvider, Message, ProviderError
from finlexpurple.selector import relevance
from finlexpurple.selector.capability_gap import CapabilityGap, detect_gaps

_WEB_AGENT = "hunter"


def _selectable_names() -> list[str]:
    """Registry names the selector may choose from: web detection + the financial family.

    Derived from the live registry so it never drifts out of sync; the selector's
    returned names are always a subset of this set.
    """

    return [agent.name for agent in registered_agents()
            if agent.family == "financial" or agent.name == _WEB_AGENT]


class _SelectedAgents(BaseModel):
    """Schema the provider must return: agent names to run, in order.

    ``extra="forbid"`` rejects any additional keys, so a response that tries to
    smuggle extra instructions fails validation and triggers the safe fallback.
    """

    model_config = ConfigDict(extra="forbid")
    agent_names: list[str]


@dataclass(frozen=True)
class Selection:
    """The selector's result: ordered agent names, capability gaps, and its source.

    ``source`` is ``"llm"`` when a bounded model pass produced the ordering, or
    ``"deterministic"`` when relevance selection did (no provider, too few
    candidates to bother a model, a provider error, or non-conforming output).
    """

    agents: list[str]
    gaps: list[CapabilityGap] = field(default_factory=list)
    source: str = "deterministic"


def select(
    corpus: str,
    endpoints: Sequence[object],
    provider: LLMProvider | None = None,
    fingerprint: object | None = None,
) -> Selection:
    """Select and order the specialists to run; capability gaps are always reported.

    Deterministic relevance is computed first (the fallback and the candidate
    baseline). With no provider, or fewer than two candidates, that baseline is
    returned without troubling a model. Otherwise one bounded call is made from
    **categorical-only** signals (agent roles, detected gateway names, endpoint
    *count*, capability-gap technologies — never URLs, params, or bodies); its
    ``agent_names`` are accepted only when they are a duplicate-free subset of the
    registry's selectable names, and any error or mismatch returns the baseline.
    """

    baseline = relevance.relevant_agents(corpus, endpoints, fingerprint)
    gaps = detect_gaps(corpus)
    if provider is None or len(baseline) < 2:
        return Selection(agents=baseline, gaps=gaps, source="deterministic")

    universe = set(_selectable_names())
    signals: dict[str, object] = {
        "selectable_agents": [
            {"name": agent.name, "role": agent.role}
            for agent in registered_agents() if agent.name in universe
        ],
        "detected_gateways": [gw.name for gw in gateway_profiles.identify_gateways(corpus)],
        "endpoint_count": len(endpoints),
        "capability_gaps": [gap.technology for gap in gaps],
        "deterministic_suggestion": baseline,
    }
    prompt = json.dumps(signals, sort_keys=True, separators=(",", ":"))
    try:
        response = provider.complete(
            [
                Message(role="system", content=(
                    "Select and order which of selectable_agents to run against this target. "
                    "Return agent_names as a subset of selectable_agents, in run order. "
                    "Never add a name that is not in selectable_agents.")),
                Message(role="user", content=prompt),
            ],
            response_schema=_SelectedAgents,
        )
        structured = response.structured
        requested = structured.agent_names if isinstance(structured, _SelectedAgents) else []
        if (
            requested
            and len(set(requested)) == len(requested)       # no duplicates
            and set(requested) <= universe                  # only registry names, never invented
            and all(get_agent(name) is not None for name in requested)
        ):
            return Selection(agents=list(requested), gaps=gaps, source="llm")
    except ProviderError:
        # Provider availability affects selection only, never safety; fall back.
        return Selection(agents=baseline, gaps=gaps, source="deterministic")
    return Selection(agents=baseline, gaps=gaps, source="deterministic")
