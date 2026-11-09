"""Per-target run context for chat scanning (chat-only; imports rich + the pipeline).

Assembles exactly the collaborators the CLI ``run`` command builds for an isolated
agent run — a default-deny egress policy, a budget-capped + rate-limited prober, a
scope-safe recon closure, the Phase 8 approval gate, and the in-scope read-back
confirmers (``verifier.read_back``) — but with the gate wired **interactive** to the
chat's human-approval prompt (``tui.gate.make_gate_confirm``).

Nothing here loosens a gate or a cap (decision D). The egress allow-list, the
per-target request kill-ceiling, and the hard-gated categories are the same objects
and policy the CLI uses; the only difference is that a present human answers the
gate in the chat instead of the run pausing non-interactively. A hard-gated
category (teller/vault/mcp) still always requires approval and can never be
config-allowed — the agent only proposes; the human at the keyboard decides.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from rich.console import Console

from finlexpurple.agents.registry import AgentRequest
from finlexpurple.config import Config, ConfigurationError
from finlexpurple.detectors.prober import HttpProber
from finlexpurple.detectors.schema import Finding
from finlexpurple.finance.idor_identities import IdorIdentities
from finlexpurple.finance.idor_identities import load_identities as load_idor_identities
from finlexpurple.gates.approval_gate import ApprovalGate
from finlexpurple.gates.authorization import record_attestation
from finlexpurple.orchestrator.persistence import create_run_directory
from finlexpurple.recon.crawler import run_recon
from finlexpurple.recon.endpoint_catalog import Endpoint
from finlexpurple.scope.models import ScopeDefinition, Target
from finlexpurple.security.audit_log import AuditLog
from finlexpurple.security.budget import RateLimiter, RequestBudget
from finlexpurple.security.egress_policy import EgressPolicy
from finlexpurple.tui.gate import make_gate_confirm
from finlexpurple.verifier import read_back

# The per-run request kill-ceiling for the chat prober — the SAME §15 cap the CLI
# scan/run uses (``finlexpurple.cli._DETECTION_REQUEST_BUDGET``). Re-stated here so
# the chat module does not import the typer CLI; a test asserts the two never drift.
DETECTION_REQUEST_BUDGET = 2000


def _require_human_approval() -> bool:
    """The configured approval policy, defaulting to *always ask* when config is uncertain.

    Honors ``REQUIRE_HUMAN_APPROVAL`` from the loaded config (the same setting the
    CLI honors) and fails safe to ``True`` — always ask the human — whenever the
    config cannot be loaded. This never loosens the gate: a hard-gated category
    requires approval regardless of this value.
    """

    try:
        return Config.load().require_human_approval
    except (ConfigurationError, ValueError, OSError):
        return True


@dataclass(frozen=True)
class RunContext:
    """The scope-safe collaborators for one chat scan of a confirmed target.

    Built by :func:`build_run_context`. ``agent_request`` produces the
    :class:`AgentRequest` an isolated agent run needs — the same bundle the CLI
    ``run`` command assembles, so a chat run reaches exactly the status a CLI run
    would, by construction.
    """

    target: Target
    origin: str
    run_dir: Path
    audit: AuditLog
    prober: HttpProber
    gate: ApprovalGate
    recon: Callable[[str], list[Endpoint]]
    idor_identities: IdorIdentities | None
    order_status_url: str | None = None

    def agent_request(self, *, findings: Iterable[Finding] = ()) -> AgentRequest:
        """Build the AgentRequest for an isolated agent run against this target."""

        return AgentRequest(
            target=self.target.canonical,
            findings=tuple(findings),
            recon=self.recon,
            prober=self.prober,
            gate=self.gate,
            charge_confirmer=read_back.charge_confirmer_for(self.prober),
            settlement_confirmer=read_back.settlement_confirmer_for(self.prober, self.order_status_url),
            coupon_confirmer=read_back.coupon_confirmer_for(self.prober, self.order_status_url),
            payment_status_confirmer=read_back.payment_status_confirmer_for(
                self.prober, self.order_status_url
            ),
            refund_confirmer=read_back.refund_confirmer_for(self.prober, self.order_status_url),
            race_confirmer=read_back.race_confirmer_for(self.prober, self.order_status_url),
            idor_identities=self.idor_identities,
        )


def build_run_context(
    target: Target,
    *,
    confirmed_scope: ScopeDefinition,
    console: Console,
    ask: Callable[[str], str],
    request_delay: float = 0.5,
    order_status_url: str | None = None,
    reports_dir: Path | None = None,
) -> RunContext:
    """Assemble the scope-safe run context for a confirmed URL ``target``.

    Builds the default-deny egress policy around the target host, the budget-capped
    + rate-limited prober, the scope-safe recon closure, the run's audit log (with
    the authorization attestation recorded from the confirmed scope's timestamp),
    and the **interactive** approval gate whose human prompt is the chat gate. May
    raise :class:`finlexpurple.finance.idor_identities.IdorConfigError` if the
    optional order-IDOR identities file is present but malformed (the caller
    surfaces it), matching the CLI's refuse-rather-than-silently-skip behavior.
    """

    parts = urlsplit(target.canonical)
    origin = f"{parts.scheme}://{parts.netloc}"
    _, run_dir = create_run_directory(target.canonical, reports_dir=reports_dir)
    audit = AuditLog(run_dir / "audit.jsonl")
    record_attestation(
        audit,
        target=target.canonical,
        attested_at=confirmed_scope.first_confirmed_at or datetime.now(timezone.utc),
    )

    prober = HttpProber(
        EgressPolicy.for_run(target_hosts=[urlsplit(origin).hostname or ""]),  # default-deny egress
        budget=RequestBudget(DETECTION_REQUEST_BUDGET),  # §15 per-target request kill-ceiling
        rate_limiter=RateLimiter(request_delay),
    )

    def _recon(url: str) -> list[Endpoint]:
        return list(run_recon(confirmed_scope, url, request_delay=request_delay).catalog.endpoints)

    # Interactive gate: a state-changing probe pauses for the human's y/N in the
    # chat. require_human_approval follows the config (fail-safe: always ask);
    # hard-gated categories always ask regardless, and are never config-allowed.
    gate = ApprovalGate(
        _require_human_approval(),
        interactive=True,
        confirm_fn=make_gate_confirm(console, ask),
        audit_log=audit,
    )

    return RunContext(
        target=target,
        origin=origin,
        run_dir=run_dir,
        audit=audit,
        prober=prober,
        gate=gate,
        recon=_recon,
        idor_identities=load_idor_identities(),
        order_status_url=order_status_url,
    )
