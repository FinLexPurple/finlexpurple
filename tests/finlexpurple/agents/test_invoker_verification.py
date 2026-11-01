"""Unit 3: an isolated specialist run verifies exactly as a scan does.

`run --agent cashier` used to return only REPORTED. With the gate + confirmers
injected into the AgentRequest, the cashier agent now reaches VERIFIED in
isolation through the same gated capture+verify helper the scan uses. A
hard-gated agent (teller) stays read-only and never verifies in isolation.
"""

from __future__ import annotations

from finlexpurple.agents import invoker
from finlexpurple.agents.registry import AgentRequest, get_agent
from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.detectors.schema import FindingStatus
from finlexpurple.gates.approval_gate import ApprovalGate
from finlexpurple.recon.endpoint_catalog import Endpoint

_CHECKOUT = Endpoint(method="GET", url="http://t/checkout", parameters=("price",), content_type=None)


class _Prober:
    def request(self, method, url, *, params=None, headers=None, body=None) -> ProbeResponse:
        return ProbeResponse(200, {}, f"total={(params or {}).get('price', '')}")


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


def test_teller_never_verifies_in_isolation() -> None:
    # Teller is read-only and hard-gated: even config-allowed, it never verifies.
    result = invoker.invoke(get_agent("teller"), _request())
    assert result.findings and all(f.status is FindingStatus.REPORTED for f in result.findings)
