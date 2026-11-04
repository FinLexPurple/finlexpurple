"""Shared gated capture+verify for the replay-backed financial classes (Unit 3).

The single source of truth used by **both** the scan path (``orchestrator.executor``
WebDetector) and an **isolated specialist run** (the cashier / ledger / ... agents
via ``agents.registry``), so a specialist run in isolation reaches exactly the
status a scan would — parity by construction, not by duplicated logic.

For one endpoint it runs the two financial classes that have a deterministic
replay — price-tampering and webhook-bypass. Each capture actively sends a
state-changing probe (a tampered request / a forged callback), so it is routed
through the Phase 8 approval ``gate`` **before** anything is sent, under the
agent's own category. On a denied / paused / absent gate nothing is sent and the
lead is kept as a passive, name-based ``reported`` candidate. Because the gate
category is the agent itself, a Teller/Vault agent is hard-gated: it can never be
config-allowed, so in a non-interactive run it never actively probes or verifies.
The verification re-execution is likewise gated and confirmed only by an in-scope
read-back; the LLM is never consulted.
"""

from __future__ import annotations

from finlexpurple.detectors.prober import Prober
from finlexpurple.detectors.schema import Finding
from finlexpurple.finance.payment_tests import coupon_abuse, price_tampering, webhook_bypass
from finlexpurple.gates.approval_gate import ApprovalGate, GateAction, GateOutcome
from finlexpurple.recon.endpoint_catalog import Endpoint
from finlexpurple.verifier import engine as verifier_engine
from finlexpurple.verifier.replay.coupon_abuse_replay import CouponConfirmer
from finlexpurple.verifier.replay.price_tampering_replay import ChargeConfirmer
from finlexpurple.verifier.replay.webhook_bypass_replay import SettlementConfirmer

# The classes this helper owns (actively captured + deterministically verified);
# any other financial check stays a passive read-only candidate elsewhere.
REPLAY_BACKED_CLASSES = ("price_tampering", "webhook_bypass", "coupon_abuse")

_PROCEED = (GateOutcome.ALLOWED, GateOutcome.APPROVED)


def _may_proceed(gate: ApprovalGate | None, *, description: str, category: str) -> bool:
    """Gate a state-changing probe; True only if the gate allows/approves it."""

    if gate is None:
        return False
    return gate.resolve(GateAction(
        description=description, category=category, state_changing=True,
    )) in _PROCEED


def capture_and_verify(
    endpoint: Endpoint,
    *,
    agent: str,
    prober: Prober | None,
    gate: ApprovalGate | None,
    charge_confirmer: ChargeConfirmer | None = None,
    settlement_confirmer: SettlementConfirmer | None = None,
    coupon_confirmer: CouponConfirmer | None = None,
) -> list[Finding]:
    """Gate -> active capture -> deterministic verify for the replay-backed classes on one endpoint.

    Returns the findings for this endpoint. Price-tampering is attempted on every
    endpoint (the capture itself only fires if a price-like parameter is present);
    webhook-bypass only on a webhook-like endpoint. Without a prober or an
    allowing gate, each stays a passive ``reported`` candidate.
    """

    findings: list[Finding] = []

    # Price-tampering: a tampered request is state-changing, so gate before sending.
    if prober is not None and _may_proceed(
        gate,
        description=f"price-tampering test (sends a tampered request) against {endpoint.url}",
        category=agent,
    ):
        price_findings = price_tampering.check([endpoint], agent=agent, prober=prober)
        for finding in price_findings:
            verifier_engine.verify(
                finding, prober=prober, gate=gate, charge_confirmer=charge_confirmer
            )
    else:
        price_findings = price_tampering.check([endpoint], agent=agent)
    findings.extend(price_findings)

    # Webhook-bypass: only webhook-like endpoints; forging a callback is state-changing.
    if webhook_bypass.looks_like_webhook(endpoint):
        if prober is not None and _may_proceed(
            gate,
            description=f"webhook-forgery test (sends a forged unsigned callback) against {endpoint.url}",
            category=agent,
        ):
            webhook_findings = webhook_bypass.check([endpoint], agent=agent, prober=prober)
            for finding in webhook_findings:
                verifier_engine.verify(
                    finding, prober=prober, gate=gate, settlement_confirmer=settlement_confirmer
                )
        else:
            webhook_findings = webhook_bypass.check([endpoint], agent=agent)
        findings.extend(webhook_findings)

    # Coupon-abuse: only coupon-like endpoints; applying a bogus coupon is
    # state-changing, so gate before sending.
    if coupon_abuse.looks_like_coupon(endpoint):
        if prober is not None and _may_proceed(
            gate,
            description=f"coupon-abuse test (applies a client-supplied coupon) against {endpoint.url}",
            category=agent,
        ):
            coupon_findings = coupon_abuse.check([endpoint], agent=agent, prober=prober)
            for finding in coupon_findings:
                verifier_engine.verify(
                    finding, prober=prober, gate=gate, coupon_confirmer=coupon_confirmer
                )
        else:
            coupon_findings = coupon_abuse.check([endpoint], agent=agent)
        findings.extend(coupon_findings)

    return findings
