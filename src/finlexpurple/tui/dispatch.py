"""The autonomous chat dispatcher (chat-only; imports rich + the provider contract).

The chat agent decides, for itself, which operation to run and when — but only among the
operations registered here, and only as far as the gates and caps allow (decision D). This
module gives the model a bounded loop: it returns a structured decision (reply, or run one
of the registered operations); the dispatcher executes the chosen operation, shows it in the
activity stream (or, for an interactive operation, lets it render and prompt the human
itself), feeds the result back, and lets the model decide again, up to a hard per-turn
operation cap. The model can **never** invent an operation outside the registry.

State-changing, egress-making work (``scan`` / ``run_agent``) is routed through the same
spine the CLI uses and never around it: the human confirms scope in the chat
(:mod:`finlexpurple.tui.scope_prompt`), the run context is the scope-safe, budget-capped,
egress-checked bundle the CLI builds (:mod:`finlexpurple.tui.scan_context`), and every
state-changing probe pauses at the **interactive** approval gate for the human's y/N. The
agent only *proposes* a target or an agent; it can never confirm its own scope, approve its
own gate, or reach a host outside the confirmed target.
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


def _deny(_prompt: str) -> str:
    """The default human-input function: denies everything (fail-safe when none is wired)."""

    return ""


class ChatAction(BaseModel):
    """The model's structured decision for one step of a turn.

    ``target`` (a URL) and ``agent`` (a named-agent name) carry the parameters for the
    ``scan`` / ``run_agent`` operations; they are ignored for a plain reply. The agent can
    only name an operation the registry already offers and an agent already registered — it
    can never invent either.
    """

    action: Literal["reply", "list_agents", "scan", "run_agent"] = "reply"
    message: str = ""  # the assistant's text when action == "reply"
    target: str = ""   # URL for scan / run_agent
    agent: str = ""    # named agent for run_agent


@dataclass(frozen=True)
class OperationResult:
    """The outcome of a registered operation: a short card summary + text fed back to the model."""

    summary: str
    text: str


@dataclass(frozen=True)
class OpContext:
    """What a registered operation is given to run: the console, the human-input fn, the decision."""

    console: Console
    ask: Callable[[str], str]
    action: ChatAction


@dataclass(frozen=True)
class Operation:
    """A registered, dispatchable operation.

    ``interactive`` marks an operation that renders and prompts the human itself (scope
    confirmation, the approval gate) — the dispatcher then does **not** wrap it in the live
    activity stream, so its prompts are never fighting a live region. A non-interactive
    operation must be read-only and is shown as one activity-stream card.
    """

    label: str
    run: Callable[[OpContext], OperationResult]
    interactive: bool = False


def _op_list_agents(ctx: OpContext) -> OperationResult:
    """Read-only: the named-agent roster (same data as ``finlexpurple agents list``)."""

    del ctx
    from finlexpurple.agents.registry import registered_agents
    from finlexpurple.gates.approval_gate import is_hard_gated

    agents = registered_agents()
    lines = []
    for agent in agents:
        tag = " (hard-gated)" if is_hard_gated(agent.name) else ""
        lines.append(f"- {agent.name} [{agent.family}] {agent.role}{tag}")
    return OperationResult(summary=f"{len(agents)} agents", text="\n".join(lines))


# Status glyphs for the interactive operations' printed step lines (the same vocabulary the
# live activity stream uses, rendered statically so they never fight an interactive prompt).
_GLYPH = {"running": ("•", "flp.running"), "done": ("✓", "flp.done"),
          "verified": ("✓", "flp.verified"), "blocked": ("⊘", "flp.blocked"),
          "failed": ("✗", "flp.muted")}


def _print_step(console: Console, status: str, text: str) -> None:
    glyph, style = _GLYPH.get(status, _GLYPH["running"])
    console.print(f"[{style}]{glyph}[/] [flp.text]{text}[/]")


def _print_findings(console: Console, findings: list) -> None:
    for finding in findings:
        console.print(
            f"  [flp.muted][{finding.status.value}][/] {finding.severity.value} "
            f"{finding.vulnerability_class} {finding.url}"
        )


def _findings_feedback(agent: str, summary: str, findings: list) -> tuple[str, OperationResult]:
    """Build the model-facing feedback text + the card summary for a completed agent run."""

    from finlexpurple.detectors.schema import FindingStatus

    verified = sum(1 for f in findings if f.status is FindingStatus.VERIFIED)
    status = "verified" if verified else "done"
    lines = [f"agent={agent} summary={summary}"]
    for finding in findings:
        lines.append(
            f"[{finding.status.value}] {finding.severity.value} "
            f"{finding.vulnerability_class} {finding.url}"
        )
    card = OperationResult(
        summary=f"{len(findings)} finding(s), {verified} verified", text="\n".join(lines)
    )
    return status, card


def _prepare_target_run(ctx: OpContext, *, agent_names: tuple[str, ...]):
    """Resolve + validate the target, confirm scope in chat, and build the scope-safe context.

    Returns ``(run_ctx, None)`` when everything is ready, or ``(None, OperationResult)`` with
    the message to feed back when the target is invalid, an agent cannot run in isolation, or
    the human did not confirm scope. ``agent_names`` are the agents the caller will invoke, so
    their requirements are checked before the human is even asked to confirm scope.
    """

    from finlexpurple.agents import invoker as agent_invoker
    from finlexpurple.agents.registry import get_agent
    from finlexpurple.finance.idor_identities import IdorConfigError
    from finlexpurple.scope.models import InvalidTargetError, Target
    from finlexpurple.tui.scan_context import build_run_context
    from finlexpurple.tui.scope_prompt import confirm_scope_in_chat

    raw = ctx.action.target.strip()
    if not raw:
        return None, OperationResult("no target", "A target URL is required (set target).")
    try:
        target = Target.parse(raw)
    except InvalidTargetError as exc:
        return None, OperationResult("invalid target", f"Invalid target: {exc}")
    if target.kind != "url":
        return None, OperationResult("need a URL", "Scanning needs a URL target (http/https).")
    available = {"target"}
    for name in agent_names:
        resolved = get_agent(name)
        if resolved is None:
            return None, OperationResult("unknown agent", f"No agent named {name!r}.")
        reason = agent_invoker.unavailable_reason(resolved, available)
        if reason is not None:
            return None, OperationResult("agent needs inputs", reason)

    scope = confirm_scope_in_chat(target, console=ctx.console, ask=ctx.ask)
    if scope is None:
        return None, OperationResult("scope not confirmed", "Scope was not confirmed; nothing was scanned.")
    try:
        run_ctx = build_run_context(
            target, confirmed_scope=scope, console=ctx.console, ask=ctx.ask
        )
    except IdorConfigError as exc:
        return None, OperationResult("order-IDOR config error", str(exc))
    return run_ctx, None


def _op_run_agent(ctx: OpContext) -> OperationResult:
    """Run one named agent against a target — scope-confirmed, egress-checked, gate-bound.

    The human confirms scope in the chat and approves every state-changing probe at the
    interactive gate; a hard-gated agent (teller/vault) is always asked and never
    config-allowed. Read-only agents (scout/hunter/sentinel/compass) make no gated probes.
    """

    from finlexpurple.agents import invoker as agent_invoker
    from finlexpurple.agents.registry import get_agent
    from finlexpurple.recon.crawler import ReconError
    from finlexpurple.scope.enforcement import OutOfScopeError

    name = ctx.action.agent.strip().lower()
    run_ctx, refusal = _prepare_target_run(ctx, agent_names=(name,))
    if refusal is not None:
        _print_step(ctx.console, "blocked", refusal.text)
        return refusal
    resolved = get_agent(name)
    assert resolved is not None and run_ctx is not None  # _prepare_target_run validated both
    _print_step(ctx.console, "running", f"run {resolved.name} against {run_ctx.target.canonical}")
    try:
        result = agent_invoker.invoke(resolved, run_ctx.agent_request())
    except (ReconError, OutOfScopeError) as exc:
        _print_step(ctx.console, "failed", f"{resolved.name}: could not run safely")
        return OperationResult("run failed", f"Agent could not run safely: {exc}")
    status, card = _findings_feedback(resolved.name, result.summary, result.findings)
    _print_step(ctx.console, status, f"{resolved.name}: {result.summary}")
    _print_findings(ctx.console, result.findings)
    return card


def _op_scan(ctx: OpContext) -> OperationResult:
    """A quick scan: recon + detection (hunter) + deterministic verification (sentinel).

    Read-only across the board — detection probes, no state-changing sends — so it makes no
    gated probes; it still confirms scope with the human and is egress-checked and
    budget-capped like every chat scan. For financial / state-changing specialist testing the
    agent uses ``run_agent`` with a specialist (e.g. cashier), which is gate-bound.
    """

    from finlexpurple.agents import invoker as agent_invoker
    from finlexpurple.agents.registry import get_agent
    from finlexpurple.recon.crawler import ReconError
    from finlexpurple.scope.enforcement import OutOfScopeError

    # Only hunter is pre-flighted (it runs from a bare target); sentinel is fed hunter's
    # findings at invoke time, so its findings requirement is satisfied at runtime.
    run_ctx, refusal = _prepare_target_run(ctx, agent_names=("hunter",))
    if refusal is not None:
        _print_step(ctx.console, "blocked", refusal.text)
        return refusal
    assert run_ctx is not None
    hunter = get_agent("hunter")
    sentinel = get_agent("sentinel")
    assert hunter is not None and sentinel is not None
    _print_step(ctx.console, "running", f"scan {run_ctx.target.canonical}")
    try:
        detected = agent_invoker.invoke(hunter, run_ctx.agent_request())
        verified = agent_invoker.invoke(
            sentinel, run_ctx.agent_request(findings=detected.findings)
        )
    except (ReconError, OutOfScopeError) as exc:
        _print_step(ctx.console, "failed", "scan: could not run safely")
        return OperationResult("scan failed", f"Scan could not run safely: {exc}")
    findings = verified.findings
    status, card = _findings_feedback("scan", verified.summary, findings)
    _print_step(ctx.console, status, f"scan: {verified.summary}")
    _print_findings(ctx.console, findings)
    return card


def default_operations() -> dict[str, Operation]:
    """The operations the chat agent may dispatch.

    ``list_agents`` is read-only (shown as an activity card). ``scan`` and ``run_agent`` are
    interactive: they confirm scope with the human and route every state-changing probe
    through the approval gate, so they render and prompt themselves rather than running inside
    the live stream.
    """

    return {
        "list_agents": Operation(label="list agents", run=_op_list_agents),
        "scan": Operation(label="scan", run=_op_scan, interactive=True),
        "run_agent": Operation(label="run agent", run=_op_run_agent, interactive=True),
    }


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
    ask: Callable[[str], str] = _deny,
    operations: dict[str, Operation] | None = None,
    max_ops: int = _MAX_OPS_PER_TURN,
) -> str:
    """Run one autonomous turn: decide -> (optionally) run a registered op -> decide -> reply.

    Returns the assistant's final reply text. Operations are bounded by ``max_ops`` and come
    only from the registry; the model cannot run anything else. ``ask`` is the human-input
    function used by interactive operations (scope confirmation, the approval gate); it
    defaults to denying, so an un-wired caller can never confirm a scan on the human's behalf.
    """

    ops = default_operations() if operations is None else operations
    convo: list[Message] = [
        Message(role="system", content=system_prompt),
        *history,
        Message(role="user", content=user_input),
    ]

    # The activity-stream region is opened lazily on the first non-interactive operation (a
    # reply-only turn, or a turn of only interactive ops, shows no shared stream) and spans
    # the ops loop, freezing into scrollback on exit.
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
            op_ctx = OpContext(console=console, ask=ask, action=decision)
            if operation.interactive:
                # Self-rendering: it prints its own steps and prompts the human directly, so
                # it never runs inside the live region.
                result = operation.run(op_ctx)
            else:
                if stream is None:
                    stream = region.enter_context(ActivityStream(console))
                index = stream.start(operation.label)
                result = operation.run(op_ctx)
                stream.finish(index, detail=result.summary)
            convo.append(Message(role="assistant", content=f"[ran {decision.action}]"))
            convo.append(Message(role="user", content=f"[result of {decision.action}]\n{result.text}"))
        # Hit the per-turn operation cap: ask once more for a final reply only.
        convo.append(Message(role="user", content="Reply to the user now with your findings."))
        try:
            return _decide(provider, convo).message or "(no reply)"
        except ProviderError as exc:
            return f"**Provider error:** {exc}"
