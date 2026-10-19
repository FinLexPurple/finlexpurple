"""Deterministic guardrail on LLM-proposed actions (Phase 7; decisions.md §28 item 9).

Extends Phase 6's planner-ordering-only boundary. Before any action the model
proposes is executed, **code** — not another prompt — validates that it is (a)
one of an explicit set of allowed categories and (b) if it names a destination,
within the egress allow-list. The model can never cause an arbitrary command to
run: an action that carries a raw command/shell/exec field, names an unknown
category, or is not a well-formed structured action is rejected outright.

This is deliberately a small, closed allow-list check, not a sanitizer — the
safe set is enumerated and everything outside it is refused.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from typing import Any

from finlexpurple.security.egress_policy import EgressBlockedError, EgressPolicy

logger = logging.getLogger(__name__)

# Keys an action may never contain: these would turn model output into a raw
# command. Their mere presence rejects the action.
_FORBIDDEN_KEYS = frozenset({"command", "cmd", "shell", "exec", "argv", "script", "eval"})


class GuardrailError(ValueError):
    """An LLM-proposed action was refused by the deterministic guardrail."""


class ActionGuardrail:
    """Validates structured, LLM-proposed actions against a closed allow-list.

    ``allowed_categories`` is the exact set of action categories a caller
    permits (e.g. a detector phase declares which detector categories it will
    run). An optional ``egress_policy`` additionally confirms any destination
    host/url the action names is reachable. Anything else is refused by code.
    """

    def __init__(
        self,
        allowed_categories: Iterable[str],
        *,
        egress_policy: EgressPolicy | None = None,
    ) -> None:
        self._allowed = frozenset(allowed_categories)
        self._egress = egress_policy

    def validate(self, action: Any) -> None:
        """Raise :class:`GuardrailError` unless ``action`` is allowed; else return.

        An allowed action is a mapping with a ``category`` in the allow-list, no
        forbidden command-carrying key, and (if it names a ``host`` or ``url``)
        a destination the egress policy permits.
        """

        if not isinstance(action, Mapping):
            self._reject("proposed action is not a structured object")
        forbidden = _FORBIDDEN_KEYS.intersection(action)
        if forbidden:
            self._reject(f"proposed action carries forbidden key(s): {sorted(forbidden)}")
        category = action.get("category")
        if not isinstance(category, str) or category not in self._allowed:
            self._reject(f"proposed action category {category!r} is not in the allow-list")
        if self._egress is not None:
            self._check_destination(action)

    def _check_destination(self, action: Mapping[str, Any]) -> None:
        assert self._egress is not None
        try:
            url = action.get("url")
            if isinstance(url, str) and url:
                self._egress.check_url(url)
            host = action.get("host")
            if isinstance(host, str) and host:
                self._egress.check_host(host)
        except EgressBlockedError as exc:
            self._reject(f"proposed action destination is out of scope: {exc}")

    def _reject(self, reason: str) -> None:
        logger.warning("Guardrail refused an LLM-proposed action: %s", reason)
        raise GuardrailError(f"Action refused by guardrail: {reason}.")
