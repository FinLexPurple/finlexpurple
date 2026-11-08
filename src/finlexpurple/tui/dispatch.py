"""The autonomous chat dispatcher (chat-only; imports rich + the provider contract).

The chat agent decides, for itself, which operation to run and when — but only among the
operations registered here, and only as far as the gates and caps allow (decision D). This
module gives the model a bounded loop: it returns a structured decision (reply, or run one
of the registered operations); the dispatcher executes the chosen operation, shows it in the
activity stream, feeds the result back, and lets the model decide again, up to a hard
per-turn operation cap. The model can **never** invent an operation outside the registry,
and a state-changing operation (when one is wired) runs only through the existing approval
gate — the dispatcher never bypasses it.

Phase 3 registers the **read-only** operations that are safe to run from chat (listing the
named agents). State-changing, egress-making operations (scanning) are deliberately not
registered here yet: wiring them must route through scope confirmation, the egress policy,
and the approval gate unchanged, which is a separate, dedicated step.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import Literal

from pydantic import BaseModel
from rich.console import Console

from finlexpurple.providers.base import LLMProvider, Message, ProviderError
from finlexpurple.tui.activity import ActivityStream

# A hard per-turn cap on how many operations the agent may chain before it must reply.
# This is one of the caps that bind the autonomy (decision D); it is not overridable here.
_MAX_OPS_PER_TURN = 4


class ChatAction(BaseModel):
    """The model's structured decision for one step of a turn."""

    action: Literal["reply", "list_agents"] = "reply"
    message: str = ""  # the assistant's text when action == "reply"


@dataclass(frozen=True)
class OperationResult:
    """The outcome of a registered operation: a short card summary + text fed back to the model."""

    summary: str
    text: str


@dataclass(frozen=True)
class Operation:
    """A registered, dispatchable operation. ``run`` must be read-only unless gated elsewhere."""

    label: str
    run: Callable[[], OperationResult]


def _op_list_agents() -> OperationResult:
    """Read-only: the named-agent roster (same data as ``finlexpurple agents list``)."""

    from finlexpurple.agents.registry import registered_agents
    from finlexpurple.gates.approval_gate import is_hard_gated

    agents = registered_agents()
    lines = []
    for agent in agents:
        tag = " (hard-gated)" if is_hard_gated(agent.name) else ""
        lines.append(f"- {agent.name} [{agent.family}] {agent.role}{tag}")
    return OperationResult(summary=f"{len(agents)} agents", text="\n".join(lines))


def default_operations() -> dict[str, Operation]:
    """The read-only operations the chat agent may dispatch in Phase 3."""

    return {"list_agents": Operation(label="list agents", run=_op_list_agents)}


def _decide(provider: LLMProvider, convo: list[Message]) -> ChatAction:
    """Ask the provider for one structured decision; fall back to its text as a reply."""

    response = provider.complete(convo, response_schema=ChatAction)
    if isinstance(response.structured, ChatAction):
        return response.structured
    # Provider did not return structured output: treat its text as a plain reply.
    return ChatAction(action="reply", message=response.content)


def dispatch_turn(
    *,
    provider: LLMProvider,
    console: Console,
    system_prompt: str,
    user_input: str,
    history: list[Message],
    operations: dict[str, Operation] | None = None,
    max_ops: int = _MAX_OPS_PER_TURN,
) -> str:
    """Run one autonomous turn: decide -> (optionally) run a registered op -> decide -> reply.

    Returns the assistant's final reply text. Operations are bounded by ``max_ops`` and come
    only from the registry; the model cannot run anything else.
    """

    ops = default_operations() if operations is None else operations
    convo: list[Message] = [
        Message(role="system", content=system_prompt),
        *history,
        Message(role="user", content=user_input),
    ]

    # The activity-stream region is opened lazily on the first operation (a reply-only
    # turn shows no stream) and spans the whole ops loop, freezing into scrollback on exit.
    with contextlib.ExitStack() as region:
        stream: ActivityStream | None = None
        for _ in range(max_ops):
            try:
                decision = _decide(provider, convo)
            except ProviderError as exc:
                return f"**Provider error:** {exc}"
            if decision.action == "reply":
                return decision.message or "(no reply)"
            operation = ops.get(decision.action)
            if operation is None:  # a non-registered action is refused, not invented
                return f"(the agent asked for an unavailable operation: {decision.action!r})"
            if stream is None:
                stream = region.enter_context(ActivityStream(console))
            index = stream.start(operation.label)
            result = operation.run()
            stream.finish(index, detail=result.summary)
            convo.append(Message(role="assistant", content=f"[ran {decision.action}]"))
            convo.append(Message(role="user", content=f"[result of {decision.action}]\n{result.text}"))
        # Hit the per-turn operation cap: ask once more for a final reply only.
        convo.append(Message(role="user", content="Reply to the user now with your findings."))
        try:
            return _decide(provider, convo).message or "(no reply)"
        except ProviderError as exc:
            return f"**Provider error:** {exc}"
