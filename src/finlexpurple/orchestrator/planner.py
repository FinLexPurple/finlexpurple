"""Deterministic action planning with optional catalog-only LLM prioritization.

This module satisfies the architecture.md Phase 6 acceptance item that *the
planner's LLM use is isolated to prioritization only*. The set of actions to
run is derived deterministically from the endpoint catalog; a provider, if
present, may only reorder that fixed set. The model can never add, drop, or
invent an action, and if its response is in any way unexpected the planner
falls back to the deterministic order. The prompt is built from an explicit
allow-list of catalog fields so no request/response values or secrets reach
the model.
"""

from __future__ import annotations

import json
from typing import Any

from pydantic import BaseModel, ConfigDict

from finlexpurple.providers.base import LLMProvider, Message, ProviderError


class _PriorityOrder(BaseModel):
    """Schema the provider must return: a bare list of action_ids to run in order.

    ``extra="forbid"`` rejects any additional keys, so a response that tries to
    smuggle extra instructions fails validation and triggers the safe fallback.
    """

    model_config = ConfigDict(extra="forbid")
    action_ids: list[str]


class Planner:
    """Plan inert Phase 8 detector calls from Phase 5 endpoint metadata.

    One action is produced per catalog endpoint. The optional ``provider`` only
    influences ordering; the actions themselves are fixed by the catalog.
    """

    def __init__(self, provider: LLMProvider | None = None) -> None:
        """Store the optional provider used solely to reorder planned actions."""

        self.provider = provider

    def plan(self, catalog: list[dict[str, Any]], completed_ids: set[str]) -> list[dict[str, Any]]:
        """Return the still-pending actions, optionally reordered by the provider.

        ``catalog`` is the list of structured endpoint records from recon;
        ``completed_ids`` are action ids already observed, so a resumed run does
        not re-plan finished work. Each action is
        ``{"action_id", "detector": "phase8_stub", "endpoint": <record>}`` with a
        stable, index-derived ``action_id``. With a provider and at least two
        pending actions, the model is asked only to prioritize; its ordering is
        accepted only if it is an exact permutation of the pending ids, and any
        provider error or mismatch returns the deterministic order unchanged.
        """

        remaining: list[dict[str, Any]] = [
            {"action_id": f"stub-{index:04d}", "detector": "phase8_stub", "endpoint": item}
            for index, item in enumerate(catalog)
            if f"stub-{index:04d}" not in completed_ids
        ]
        if not self.provider or len(remaining) < 2:
            return remaining
        # Construct the prompt from an explicit allow-list of catalog fields only.
        safe_catalog = [
            {
                "action_id": action["action_id"],
                "path": action["endpoint"]["path"],
                "parameter_names": action["endpoint"]["parameter_names"],
                "content_type": action["endpoint"]["content_type"],
            }
            for action in remaining
        ]
        prompt = json.dumps(safe_catalog, sort_keys=True, separators=(",", ":"))
        try:
            response = self.provider.complete(
                [Message(role="system", content="Prioritize these endpoint metadata records. Return only action_ids."),
                 Message(role="user", content=prompt)],
                response_schema=_PriorityOrder,
            )
            structured = response.structured
            requested = structured.action_ids if isinstance(structured, _PriorityOrder) else []
            by_id = {action["action_id"]: action for action in remaining}
            if len(requested) == len(remaining) and set(requested) == set(by_id):
                return [by_id[action_id] for action_id in requested]
        except ProviderError:
            # Provider availability affects ordering only, never safety or execution.
            return remaining
        return remaining
