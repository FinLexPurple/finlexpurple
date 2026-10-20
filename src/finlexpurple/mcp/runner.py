"""MCP assessment runner (Phase 9; decisions.md §24, §28 items 4 & 10).

Drives the offensive testers and the passive scan into one assessment. Every
offensive probe manipulates a live agent, so each is a **state-changing**,
hard-gated step: it runs only if the Phase 8 approval gate returns APPROVED for
the ``mcp`` category — which is hard-gated and cannot be disabled by config, so
with no human approval the probes pause and are not executed. Offensive probes
are additionally bounded by the per-target request kill-ceiling (§28 #4) and an
optional rate limiter. The passive mcp-scan wrap is read-only and ungated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from finlexpurple.detectors.schema import Finding
from finlexpurple.gates.approval_gate import ApprovalGate, GateAction, GateOutcome
from finlexpurple.mcp.connector import AgentConnector, Canary
from finlexpurple.mcp.exfiltration_oracle import detect_exfiltration
from finlexpurple.mcp.passive_scan import run_passive_scan
from finlexpurple.mcp.prompt_injection import detect_prompt_injection
from finlexpurple.mcp.tool_poisoning import detect_tool_poisoning
from finlexpurple.security.budget import RateLimiter, RequestBudget, RequestBudgetExceededError


@dataclass
class MCPAssessmentResult:
    """Outcome of an MCP assessment: findings plus how the gate disposed of each probe."""

    findings: list[Finding] = field(default_factory=list)
    executed_probes: int = 0
    gated_probes: int = 0  # offensive probes the gate did not approve (paused/denied)
    budget_stopped: bool = False


def assess_mcp(
    connector: AgentConnector,
    *,
    gate: ApprovalGate,
    canary: Canary | None = None,
    config_path: Path | None = None,
    rate_limiter: RateLimiter | None = None,
    budget: RequestBudget | None = None,
    agent: str = "mcp",
) -> MCPAssessmentResult:
    """Run the offensive probes (hard-gated) and, if given a config, the passive scan."""

    result = MCPAssessmentResult()
    probes: list[tuple[str, object]] = [
        ("prompt_injection", lambda: detect_prompt_injection(connector, agent=agent)),
        ("tool_poisoning", lambda: detect_tool_poisoning(connector, agent=agent)),
    ]
    if canary is not None:
        probes.append(("data_exfiltration", lambda: detect_exfiltration(connector, canary, agent=agent)))

    for name, run_probe in probes:
        # Every offensive probe is state-changing and hard-gated (category 'mcp').
        action = GateAction(f"MCP offensive probe: {name}", "mcp", state_changing=True)
        if gate.resolve(action) is not GateOutcome.APPROVED:
            result.gated_probes += 1
            continue  # PAUSED or DENIED -> do not run the probe
        if budget is not None:
            try:
                budget.charge()  # per-target kill-ceiling
            except RequestBudgetExceededError:
                result.budget_stopped = True
                break
        if rate_limiter is not None:
            rate_limiter.acquire()
        result.findings.extend(run_probe())  # type: ignore[operator]
        result.executed_probes += 1

    # Passive mcp-scan is read-only, so it is not gated.
    if config_path is not None:
        result.findings.extend(run_passive_scan(config_path, agent=agent))
    return result
