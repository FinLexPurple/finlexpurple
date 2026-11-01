"""Unit 3: an isolated specialist run verifies exactly as a scan does.

`run --agent cashier` used to return only REPORTED. With the gate + confirmers
injected into the AgentRequest, the cashier agent now reaches VERIFIED in
isolation through the same gated capture+verify helper the scan uses. A
hard-gated agent (teller) stays read-only and never verifies in isolation.
"""

from __future__ import annotations

from finlexpurple.agents import invoker
from finlexpurple.agents.registry import AgentRequest, get_agent
from finlexpurple.cli import _settlement_confirmer_for
from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.detectors.schema import FindingStatus
from finlexpurple.finance.payment_tests import webhook_bypass
from finlexpurple.gates.approval_gate import ApprovalGate
from finlexpurple.recon.endpoint_catalog import Endpoint

_CHECKOUT = Endpoint(method="GET", url="http://t/checkout", parameters=("price",), content_type=None)
_WEBHOOK = Endpoint(method="POST", url="http://t/payment/webhook", parameters=(), content_type=None)
_ORACLE_URL = "http://t/orders/{order_id}"


class _Prober:
    def request(self, method, url, *, params=None, headers=None, body=None) -> ProbeResponse:
        return ProbeResponse(200, {}, f"total={(params or {}).get('price', '')}")


class _WebhookProber:
    """Accepts the forged POST (200); a GET of the SEPARATE /orders/<id> oracle shows paid per ``paid``."""

    def __init__(self, *, paid: bool) -> None:
        self._paid = paid

    def request(self, method, url, *, params=None, headers=None, body=None) -> ProbeResponse:
        if body is not None:  # forged callback (capture + replay)
            return ProbeResponse(200, {}, "received")
        if "/orders/" in url:  # the separate order-status oracle
            status = webhook_bypass.PAID_MARKER if self._paid else "pending"
            order_id = url.rsplit("/", 1)[-1]
            return ProbeResponse(200, {}, f'{{"order_id": "{order_id}", "status": "{status}"}}')
        return ProbeResponse(200, {}, "no order state here")


def _config_allow() -> ApprovalGate:
    return ApprovalGate(False, interactive=False)


def _request(agent_target: str = "http://t") -> AgentRequest:
    return AgentRequest(
        target=agent_target, recon=lambda _u: [_CHECKOUT], prober=_Prober(),
        gate=_config_allow(), charge_confirmer=lambda f, v: True,
    )


def test_cashier_reaches_verified_in_isolation() -> None:
    result = invoker.invoke(get_agent("cashier"), _request())
    pt = [f for f in result.findings if f.vulnerability_class == "price_tampering"]
    assert pt and pt[0].status is FindingStatus.VERIFIED
    assert "verified" in result.summary


def test_cashier_without_collaborators_stays_reported() -> None:
    # No gate/confirmers injected: the active probe is never run; nothing verifies.
    bare = AgentRequest(target="http://t", recon=lambda _u: [_CHECKOUT], prober=_Prober())
    result = invoker.invoke(get_agent("cashier"), bare)
    assert result.findings and all(f.status is FindingStatus.REPORTED for f in result.findings)


def test_cashier_webhook_bypass_verified_with_order_status_oracle() -> None:
    # Parity with scan: `run --agent cashier --order-status-url ...` reaches VERIFIED.
    prober = _WebhookProber(paid=True)
    request = AgentRequest(
        target="http://t", recon=lambda _u: [_WEBHOOK], prober=prober, gate=_config_allow(),
        settlement_confirmer=_settlement_confirmer_for(prober, _ORACLE_URL),
    )
    result = invoker.invoke(get_agent("cashier"), request)
    wh = [f for f in result.findings if f.vulnerability_class == "webhook_bypass"]
    assert wh and wh[0].status is FindingStatus.VERIFIED


def test_cashier_webhook_bypass_inconclusive_without_oracle() -> None:
    # No --order-status-url / env: the forgery is accepted but unconfirmable -> INCONCLUSIVE.
    prober = _WebhookProber(paid=True)
    request = AgentRequest(
        target="http://t", recon=lambda _u: [_WEBHOOK], prober=prober, gate=_config_allow(),
        settlement_confirmer=_settlement_confirmer_for(prober, None),
    )
    result = invoker.invoke(get_agent("cashier"), request)
    wh = [f for f in result.findings if f.vulnerability_class == "webhook_bypass"]
    assert wh and wh[0].status is FindingStatus.INCONCLUSIVE  # never VERIFIED without a real read-back


def test_teller_never_verifies_in_isolation() -> None:
    # Teller is read-only and hard-gated: even config-allowed, it never verifies.
    result = invoker.invoke(get_agent("teller"), _request())
    assert result.findings and all(f.status is FindingStatus.REPORTED for f in result.findings)
