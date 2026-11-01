"""Deterministic relevance selection over the fixed registry (Decision 1).

This is the scan's front door even with no model configured, and the selector's
fallback when a bounded LLM pass errors or returns anything non-conforming. It
chooses *which already-registered specialists run* from the Phase 5 recon corpus
and endpoint catalog, building only on Compass triage
(:mod:`finlexpurple.finance.gateway_profiles`) and endpoint shape — the same
relevance idea as :mod:`finlexpurple.detectors.dispatch`, lifted to the
agent/specialist level.

It can only return names that already exist in
:mod:`finlexpurple.agents.registry`; it never invents, adds, or renames an agent.
It selects and orders — it never verifies, gates, or mutates a finding.
"""

from __future__ import annotations

from collections.abc import Sequence

from finlexpurple.agents.registry import get_agent
from finlexpurple.finance import gateway_profiles

# Web detection (the 'hunter' agent) is the baseline for any URL target with at
# least one endpoint; the financial specialist (if any) comes from Compass.
_WEB_AGENT = "hunter"


def relevant_agents(
    corpus: str, endpoints: Sequence[object], fingerprint: object | None = None
) -> list[str]:
    """Return the ordered, registry-valid agent names worth running on this target.

    ``corpus`` is the local triage text (fingerprint + headers + endpoint paths);
    ``endpoints`` is the recon catalog (only its presence is used here). Order:
    web detection first when there are endpoints, then the single highest-risk
    financial specialist Compass recommends for the detected gateway, if any.
    Names not present in the registry are dropped, so the result is always a
    runnable subset of the fixed roster.
    """

    del fingerprint  # reserved for technology-specific narrowing later (see dispatch.py)
    selected: list[str] = []
    if endpoints:
        selected.append(_WEB_AGENT)
    specialist = gateway_profiles.recommend_specialist(gateway_profiles.identify_gateways(corpus))
    if specialist is not None:
        selected.append(specialist)
    # De-duplicate (order-preserving) and keep only names the registry actually has.
    return [name for name in dict.fromkeys(selected) if get_agent(name) is not None]
