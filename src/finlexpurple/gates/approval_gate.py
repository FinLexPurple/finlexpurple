"""Human-in-the-loop approval gate (Phase 8; decisions.md §3, §14, §24).

The safety spine. Before the orchestrator executes any action a detector/test
function has flagged **state-changing**, the gate decides whether a human must
approve it first:

* **Hard-gated categories** — ``banking``, ``teller``, ``vault``, and
  AI-agent/MCP offensive (``mcp``) — **always** require approval. This is a
  hard-coded rule: no config value, environment variable, or plan tier can turn
  it off (decisions.md §3/§14/§24). ``needs_approval`` returns ``True`` for these
  regardless of ``REQUIRE_HUMAN_APPROVAL``, and ``resolve`` can never return
  ``ALLOWED`` for one.
* **Everything else state-changing** follows ``Config.REQUIRE_HUMAN_APPROVAL``
  (default true).
* **Non-state-changing** actions are never gated.

When approval is needed, an interactive run prompts the operator; a
non-interactive run returns ``PAUSED`` so the caller can persist state and exit
cleanly, resumable later. Decisions are recorded in the tamper-evident audit
log when one is supplied.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from finlexpurple.security.audit_log import AuditLog

logger = logging.getLogger(__name__)

# Categories whose state-changing actions ALWAYS pause — never overridable.
HARD_GATED_CATEGORIES = frozenset({"banking", "teller", "vault", "mcp"})


class GateOutcome(str, Enum):
    """The result of evaluating an action against the gate."""

    ALLOWED = "allowed"        # not gated (non-state-changing, or config-approved)
    APPROVED = "approved"      # a human approved it interactively
    DENIED = "denied"          # a human declined it
    PAUSED = "paused"          # approval needed but no human present; resumable


@dataclass(frozen=True)
class GateAction:
    """An action the gate evaluates. ``state_changing`` is set per test, never inferred."""

    description: str
    category: str
    state_changing: bool


def is_hard_gated(category: str) -> bool:
    """Return True if a category is hard-gated (approval can never be disabled)."""

    return category.strip().lower() in HARD_GATED_CATEGORIES


class ApprovalGate:
    """Evaluates actions against the approval policy and records the decision."""

    def __init__(
        self,
        require_human_approval: bool,
        *,
        interactive: bool,
        confirm_fn: Callable[[str], bool] | None = None,
        audit_log: AuditLog | None = None,
    ) -> None:
        self.require_human_approval = require_human_approval
        self.interactive = interactive
        self._confirm = confirm_fn
        self._audit = audit_log

    def needs_approval(self, action: GateAction) -> bool:
        """The hard rule: hard-gated state-changing actions always need approval."""

        if not action.state_changing:
            return False
        if is_hard_gated(action.category):
            return True  # not overridable by config
        return self.require_human_approval

    def resolve(self, action: GateAction) -> GateOutcome:
        """Decide the action's fate; prompt if interactive, else pause.

        Never returns ``ALLOWED`` for an action that needs approval — a
        hard-gated state-changing action can only end as APPROVED (a human said
        yes), DENIED (a human said no), or PAUSED (no human present).
        """

        if not self.needs_approval(action):
            return self._record(action, GateOutcome.ALLOWED)
        if not self.interactive:
            logger.warning(
                "Approval required for %s action %r; pausing (no interactive operator).",
                action.category,
                action.description,
            )
            return self._record(action, GateOutcome.PAUSED)
        if self._confirm is None:
            raise RuntimeError("Interactive approval requested but no confirm function was provided.")
        prompt = (
            f"Approve {action.category} action that may change state: "
            f"{action.description}?"
        )
        outcome = GateOutcome.APPROVED if self._confirm(prompt) else GateOutcome.DENIED
        return self._record(action, outcome)

    def _record(self, action: GateAction, outcome: GateOutcome) -> GateOutcome:
        if self._audit is not None:
            self._audit.record(
                "approval_decision",
                description=action.description,
                category=action.category,
                state_changing=action.state_changing,
                hard_gated=is_hard_gated(action.category),
                outcome=outcome.value,
            )
        return outcome
