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

import logging
from collections.abc import Callable
from dataclasses import dataclass

from finlexpurple.detectors.dispatch import run_relevant
from finlexpurple.detectors.prober import Prober
from finlexpurple.detectors.schema import Finding, FindingStatus
from finlexpurple.finance.idor_identities import IdorIdentities
from finlexpurple.gates.approval_gate import ApprovalGate
from finlexpurple.recon.endpoint_catalog import Endpoint
from finlexpurple.verifier import engine as verifier_engine
from finlexpurple.verifier.replay.coupon_abuse_replay import CouponConfirmer
from finlexpurple.verifier.replay.price_tampering_replay import ChargeConfirmer
from finlexpurple.verifier.replay.webhook_bypass_replay import SettlementConfirmer

# Requirement vocabulary an agent may declare (what an isolated run needs).
TARGET = "target"
FINDINGS = "findings"
SOURCE = "source"
MCP_CONFIG = "mcp_config"

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class AgentRequest:
    """Inputs an isolated agent run may use; all optional and injectable.

    ``recon`` maps a target URL to its endpoints and ``prober`` is the scope-safe
    HTTP prober — both injected by the caller (the CLI builds real ones; tests
    pass fakes), so an agent never reaches outside what it is given. ``gate`` and
    the two confirmers are the verification collaborators (Unit 3): with them a
    financial specialist run in isolation reaches ``verified`` exactly as in a
    scan; without them its findings stay ``reported`` candidates, never verified.
    """

    target: str | None = None
    findings: tuple[Finding, ...] = ()
    recon: Callable[[str], list[Endpoint]] | None = None
    prober: Prober | None = None
    gate: ApprovalGate | None = None
    charge_confirmer: ChargeConfirmer | None = None
    settlement_confirmer: SettlementConfirmer | None = None
    coupon_confirmer: CouponConfirmer | None = None
    # Two-session identities for active order-IDOR (Unit 2.1); absent => order-IDOR
    # is not actively verified in isolation and stays a passive candidate.
    idor_identities: IdorIdentities | None = None


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


# --- Financial agents (Phase 19a). finance/ is imported lazily inside each entry
#     point so the registry has no import cycle with the finance package. --------


def _compass(request: AgentRequest) -> AgentResult:
    """Triage: fingerprint the target (read-only) and recommend a specialist."""

    assert request.target is not None
    from finlexpurple.finance import gateway_profiles

    corpus = request.target
    if request.prober is not None:
        try:
            response = request.prober.request("GET", request.target)
            corpus += "\n" + " ".join(f"{k}:{v}" for k, v in response.headers.items())
            corpus += "\n" + response.text
        except Exception as exc:  # noqa: BLE001 - triage is best-effort; recon paths still inform it
            logger.debug("Compass fingerprint GET failed; using recon paths only: %s", exc)
    if request.recon is not None:
        corpus += "\n" + "\n".join(endpoint.url for endpoint in request.recon(request.target))
    gateways = gateway_profiles.identify_gateways(corpus)
    recommended = gateway_profiles.recommend_specialist(gateways)
    names = ", ".join(gateway.name for gateway in gateways) or "none detected"
    return AgentResult(
        "compass", [], 0, f"gateways: {names}; recommended specialist: {recommended or 'none'}"
    )


def _run_payment_specialist(request: AgentRequest, *, name: str, note: str) -> AgentResult:
    """Run a standard-gate financial specialist in isolation, reaching VERIFIED like a scan.

    The replay-backed classes (price-tampering, webhook-bypass) go through the
    SAME gated capture+verify helper the scan path uses, so an isolated run
    reaches the same status; the remaining read-only surface checks stay passive
    ``reported`` candidates. Verification needs the injected gate + confirmers;
    absent them the gate blocks the active probe and findings stay candidates.
    """

    assert request.target is not None and request.recon is not None
    from finlexpurple.finance import payment_tests
    from finlexpurple.finance.payment_tests import financial_specialist, order_idor

    endpoints = request.recon(request.target)
    findings: list[Finding] = []
    for endpoint in endpoints:
        findings.extend(financial_specialist.capture_and_verify(
            endpoint, agent=name, prober=request.prober, gate=request.gate,
            charge_confirmer=request.charge_confirmer,
            settlement_confirmer=request.settlement_confirmer,
            coupon_confirmer=request.coupon_confirmer,
        ))
    # Active order-IDOR (two-session cross-account read) when identities are
    # configured — the SAME helper the scan path uses, so an isolated specialist
    # run reaches the same status. A read, so ungated.
    idor_findings = order_idor.run_order_idor(
        request.target, agent=name, prober=request.prober, identities=request.idor_identities,
    )
    findings.extend(idor_findings)
    # The remaining read-only surface checks stay passive candidates (reported).
    # Skip the replay-backed classes and, when order-IDOR was actively verified,
    # its passive duplicate too.
    actively_verified = set(financial_specialist.REPLAY_BACKED_CLASSES)
    if idor_findings:
        actively_verified.add("order_idor")
    findings.extend(
        finding for finding in payment_tests.run_all(endpoints, agent=name)
        if finding.vulnerability_class not in actively_verified
    )
    verified = sum(1 for finding in findings if finding.status is FindingStatus.VERIFIED)
    return AgentResult(
        name, findings, 0,
        f"{len(findings)} {note} finding(s) across {len(endpoints)} endpoint(s); "
        f"{verified} verified by deterministic replay (the rest reported; verification is gated)",
    )


def _cashier(request: AgentRequest) -> AgentResult:
    """E-commerce payment testing: actively verifies the replay-backed classes in isolation."""

    return _run_payment_specialist(request, name="cashier", note="payment")


def _teller(request: AgentRequest) -> AgentResult:
    """Banking testing: read-only by default; state-changing steps are hard-gated.

    Detection is read-only and never exploits the target; any state-changing step
    (none are performed here) must route through finance.banking_mode's hard gate,
    which no config/tier can disable.
    """

    assert request.target is not None and request.recon is not None
    from finlexpurple.finance import payment_tests

    endpoints = request.recon(request.target)
    findings = payment_tests.run_all(endpoints, agent="teller")
    return AgentResult(
        "teller", findings, 0,
        f"{len(findings)} banking finding(s), read-only; state-changing steps are hard-gated "
        "and never auto-run",
    )


# --- Financial agents (Phase 19b). Same pattern as 19a: registry entry points
#     over the shared read-only payment suite (per-agent attack taxonomies are
#     deferred until specified). Vault is hard-gated like Teller. ---------------


def _payment_agent_result(request: AgentRequest, *, name: str, note: str) -> AgentResult:
    """Run a standard-gate financial agent: same gated capture+verify as the scan path."""

    return _run_payment_specialist(request, name=name, note=note)


def _ledger(request: AgentRequest) -> AgentResult:
    """Subscription / recurring-billing testing (standard gate)."""

    return _payment_agent_result(request, name="ledger", note="subscription")


def _broker(request: AgentRequest) -> AgentResult:
    """Marketplace / multi-party payout testing (standard gate)."""

    return _payment_agent_result(request, name="broker", note="marketplace payout")


def _underwriter(request: AgentRequest) -> AgentResult:
    """Lending / Buy-Now-Pay-Later testing (standard gate)."""

    return _payment_agent_result(request, name="underwriter", note="lending/BNPL")


def _courier(request: AgentRequest) -> AgentResult:
    """Remittance / international-transfer testing (standard gate)."""

    return _payment_agent_result(request, name="courier", note="remittance")


def _vault(request: AgentRequest) -> AgentResult:
    """Crypto / Web3 testing: read-only, hard-gated like Teller (irreversible txns)."""

    assert request.target is not None and request.recon is not None
    from finlexpurple.finance import payment_tests

    endpoints = request.recon(request.target)
    findings = payment_tests.run_all(endpoints, agent="vault")
    return AgentResult(
        "vault", findings, 0,
        f"{len(findings)} crypto/Web3 finding(s), read-only; state-changing steps are hard-gated "
        "(like Teller) and never auto-run",
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
        # Financial suite — Phase 19a (the rest arrive in 19b).
        StageAgent("compass", "Triage — fingerprint the target and recommend a specialist",
                   "triage", "Phase 19a", requires=(TARGET,), family="financial", entry=_compass),
        StageAgent("cashier", "E-commerce / retail payment testing", "payments", "Phase 19a",
                   requires=(TARGET,), family="financial", entry=_cashier),
        StageAgent("teller", "Banking — read-only, hard-gated (no override, any tier)",
                   "banking", "Phase 19a", requires=(TARGET,), family="financial", entry=_teller),
        # Financial suite — Phase 19b.
        StageAgent("ledger", "Subscription / recurring billing", "payments", "Phase 19b",
                   requires=(TARGET,), family="financial", entry=_ledger),
        StageAgent("broker", "Marketplace / multi-party payouts", "payments", "Phase 19b",
                   requires=(TARGET,), family="financial", entry=_broker),
        StageAgent("vault", "Crypto / Web3 — read-only, hard-gated (no override, any tier)",
                   "crypto", "Phase 19b", requires=(TARGET,), family="financial", entry=_vault),
        StageAgent("underwriter", "Lending / Buy-Now-Pay-Later", "payments", "Phase 19b",
                   requires=(TARGET,), family="financial", entry=_underwriter),
        StageAgent("courier", "Remittance / international transfer", "payments", "Phase 19b",
                   requires=(TARGET,), family="financial", entry=_courier),
    )
}


def registered_agents() -> list[StageAgent]:
    """Return all registered agents in stable (name-sorted) order."""

    return [_AGENTS[name] for name in sorted(_AGENTS)]


def get_agent(name: str) -> StageAgent | None:
    """Return the agent with ``name``, or None if it is not registered."""

    return _AGENTS.get(name.strip().lower())
