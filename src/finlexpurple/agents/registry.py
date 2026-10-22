"""The named-agent roster (Phase 18; decisions.md §13, §14).

Maps each agent name to its role, the stage it wraps, the phase it was built in,
its declared requirements, its family, and — where it can run on its own — an
isolated entry point. Stage agents (§13) are registered here; the Phase 19
financial agents (§14) register into this same file under ``family="financial"``.

An agent's *entry point* runs just that one stage. It takes an
:class:`AgentRequest` (the inputs it may need, all injectable so a run is
isolated and testable) and returns an :class:`AgentResult`. Agents that cannot
run from a bare target alone declare what they still need via ``requires``; the
invoker turns an unmet requirement into a clean explanation rather than a crash.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from finlexpurple.detectors.dispatch import run_relevant
from finlexpurple.detectors.prober import Prober
from finlexpurple.detectors.schema import Finding, FindingStatus
from finlexpurple.recon.endpoint_catalog import Endpoint
from finlexpurple.verifier import engine as verifier_engine

# Requirement vocabulary an agent may declare (what an isolated run needs).
TARGET = "target"
FINDINGS = "findings"
SOURCE = "source"
MCP_CONFIG = "mcp_config"


@dataclass(frozen=True)
class AgentRequest:
    """Inputs an isolated agent run may use; all optional and injectable.

    ``recon`` maps a target URL to its endpoints and ``prober`` is the scope-safe
    HTTP prober — both injected by the caller (the CLI builds real ones; tests
    pass fakes), so an agent never reaches outside what it is given.
    """

    target: str | None = None
    findings: tuple[Finding, ...] = ()
    recon: Callable[[str], list[Endpoint]] | None = None
    prober: Prober | None = None


@dataclass(frozen=True)
class AgentResult:
    """The outcome of an isolated agent run."""

    agent: str
    findings: list[Finding]
    llm_calls: int
    summary: str


AgentEntry = Callable[[AgentRequest], AgentResult]


@dataclass(frozen=True)
class StageAgent:
    """Metadata for one named agent plus its optional isolated entry point."""

    name: str
    role: str
    stage: str
    phase: str
    requires: tuple[str, ...] = ()
    family: str = "stage"
    entry: AgentEntry | None = None

    @property
    def directly_invocable(self) -> bool:
        """True if the agent can run on its own (has an isolated entry point)."""

        return self.entry is not None


# --- Isolated entry points (only for agents runnable from a bare target) ------


def _scout(request: AgentRequest) -> AgentResult:
    """Recon only: map the attack surface, report no findings."""

    assert request.target is not None and request.recon is not None
    endpoints = request.recon(request.target)
    return AgentResult("scout", [], 0, f"mapped {len(endpoints)} endpoint(s); no detection run")


def _hunter(request: AgentRequest) -> AgentResult:
    """Detection only: recon, then run the web detectors — no verify/gate/fix.

    Findings come back with their initial ``reported`` status; nothing here
    promotes them to ``verified`` (that is the sentinel's job). Uses no LLM.
    """

    assert request.target is not None and request.recon is not None and request.prober is not None
    findings: list[Finding] = []
    endpoints = request.recon(request.target)
    for endpoint in endpoints:
        findings.extend(run_relevant(endpoint, request.prober))
    verified = sum(1 for f in findings if f.status is FindingStatus.VERIFIED)
    return AgentResult(
        "hunter",
        findings,
        0,
        f"{len(findings)} finding(s) across {len(endpoints)} endpoint(s); "
        f"{verified} verified (detection does not verify)",
    )


def _sentinel(request: AgentRequest) -> AgentResult:
    """Verification only: deterministically replay the findings it is given."""

    for finding in request.findings:
        verifier_engine.verify(finding, prober=request.prober)
    verified = sum(1 for f in request.findings if f.status is FindingStatus.VERIFIED)
    return AgentResult(
        "sentinel", list(request.findings), 0, f"{verified}/{len(request.findings)} verified by replay"
    )


# --- The roster ---------------------------------------------------------------

_AGENTS: dict[str, StageAgent] = {
    agent.name: agent
    for agent in (
        StageAgent("scout", "Recon / attack-surface mapping", "recon", "Phase 5",
                   requires=(TARGET,), entry=_scout),
        StageAgent("marshal", "Planning / orchestration (the full pipeline)", "orchestration",
                   "Phase 6", requires=(TARGET,), entry=None),
        StageAgent("hunter", "Web vulnerability detection (all classes)", "detection", "Phase 10",
                   requires=(TARGET,), entry=_hunter),
        StageAgent("sentinel", "Deterministic verification of findings", "verification", "Phase 11",
                   requires=(FINDINGS,), entry=_sentinel),
        StageAgent("warden", "Human-approval gate for high-risk actions", "gating", "Phase 8",
                   requires=(FINDINGS,), entry=None),
        StageAgent("forge", "Code-fix generation (JS/TS + Python)", "codefix", "Phase 15",
                   requires=(SOURCE, FINDINGS), entry=None),
        StageAgent("herald", "Reporting (report.json / report.md + bundles)", "reporting", "Phase 16",
                   requires=(FINDINGS,), entry=None),
        StageAgent("mcp", "AI-agent / MCP offensive testing", "mcp", "Phase 9",
                   requires=(MCP_CONFIG,), entry=None),
    )
}


def registered_agents() -> list[StageAgent]:
    """Return all registered agents in stable (name-sorted) order."""

    return [_AGENTS[name] for name in sorted(_AGENTS)]


def get_agent(name: str) -> StageAgent | None:
    """Return the agent with ``name``, or None if it is not registered."""

    return _AGENTS.get(name.strip().lower())
