"""Run one named agent in isolation (Phase 18).

Before running an agent, the invoker checks its declared requirements against
what the caller can actually provide. An unmet requirement — or an agent that
only runs inside the full pipeline — becomes a clear, one-paragraph explanation,
never a stack trace. When everything an agent needs is present, its isolated
entry point runs that single stage and nothing else.
"""

from __future__ import annotations

from finlexpurple.agents.registry import (
    FINDINGS,
    MCP_CONFIG,
    SOURCE,
    TARGET,
    AgentRequest,
    AgentResult,
    StageAgent,
)

# A friendly hint per requirement the caller cannot satisfy on its own.
_HINTS = {
    TARGET: "Pass --target <url>.",
    FINDINGS: (
        "Run `finlexpurple run --agent hunter --target <url>` (or a full "
        "`finlexpurple scan`) first, then this agent can act on those findings."
    ),
    SOURCE: "Point it at local source via a whitebox scan (`finlexpurple scan --path <dir>`).",
    MCP_CONFIG: "Provide an MCP configuration for the AI-agent / MCP module.",
}


def missing_requirements(agent: StageAgent, available: set[str]) -> list[str]:
    """Return the agent's declared requirements that ``available`` does not meet."""

    return [requirement for requirement in agent.requires if requirement not in available]


def unavailable_reason(agent: StageAgent, available: set[str]) -> str | None:
    """Explain why the agent cannot run in isolation, or None if it can.

    Returns a clean, user-facing paragraph (no traceback) when a requirement is
    unmet or the agent only runs inside the full pipeline; returns None when the
    agent has everything it needs and an isolated entry point.
    """

    missing = missing_requirements(agent, available)
    if missing:
        hints = " ".join(_HINTS[requirement] for requirement in missing if requirement in _HINTS)
        return (
            f"The '{agent.name}' agent needs {', '.join(missing)} before it can run on its own. "
            + hints
        )
    if agent.entry is None:
        return (
            f"The '{agent.name}' agent runs as part of the full pipeline, not on its own; "
            "run `finlexpurple scan`."
        )
    return None


def invoke(agent: StageAgent, request: AgentRequest) -> AgentResult:
    """Run the agent's isolated entry point. Caller must have checked requirements."""

    if agent.entry is None:  # defensive: unavailable_reason should have caught this
        raise ValueError(f"The '{agent.name}' agent has no isolated entry point.")
    return agent.entry(request)
