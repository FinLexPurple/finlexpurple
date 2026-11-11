"""The chat approval gate is LIVE: the human's y/N controls a real state-changing capture.

These drive the actual cashier capture+verify through the interactive gate whose confirm
function is the chat prompt (``tui.gate.make_gate_confirm``). A 'yes' lets the state-changing
price-tampering probe run and reach VERIFIED; a 'no' blocks it and the finding stays a
REPORTED candidate. This is the decision-D guarantee in action: the human at the keyboard
approves, never the model, and a denial is fully binding.
"""

from __future__ import annotations

import io

from finlexpurple.agents import invoker
from finlexpurple.agents.registry import AgentRequest, get_agent
from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.detectors.schema import FindingStatus
from finlexpurple.gates.approval_gate import ApprovalGate
from finlexpurple.recon.endpoint_catalog import Endpoint
from finlexpurple.tui.gate import make_gate_confirm
from finlexpurple.tui.theme import make_console

_CHECKOUT = Endpoint(method="GET", url="http://t/checkout", parameters=("price",), content_type=None)


class _Prober:
    """Reflects the price parameter back, so a tampered value is 'charged' on read-back."""

    def request(self, method, url, *, params=None, headers=None, body=None) -> ProbeResponse:
        return ProbeResponse(200, {}, f"total={(params or {}).get('price', '')}")


def _chat_gate(answer: str) -> ApprovalGate:
    console = make_console(file=io.StringIO(), no_color=True, width=80)
    return ApprovalGate(True, interactive=True, confirm_fn=make_gate_confirm(console, lambda _p: answer))


def _run_cashier(answer: str):
    request = AgentRequest(
        target="http://t", recon=lambda _u: [_CHECKOUT], prober=_Prober(),
        gate=_chat_gate(answer), charge_confirmer=lambda f, v: True,
    )
    return invoker.invoke(get_agent("cashier"), request)


def test_human_yes_lets_the_state_changing_probe_run_and_verify() -> None:
    result = _run_cashier("y")
    pt = [f for f in result.findings if f.vulnerability_class == "price_tampering"]
    assert pt and pt[0].status is FindingStatus.VERIFIED  # approved -> captured -> verified


def test_human_no_blocks_the_probe_and_it_stays_reported() -> None:
    result = _run_cashier("n")
    pt = [f for f in result.findings if f.vulnerability_class == "price_tampering"]
    # Denied: the tampered request was never sent; the lead stays a passive candidate.
    assert pt and all(f.status is FindingStatus.REPORTED for f in pt)


def test_hard_gated_teller_never_captures_even_on_yes() -> None:
    # Teller is read-only and hard-gated: even with the human saying yes it never
    # actively probes or verifies (it performs no state-changing capture at all).
    request = AgentRequest(
        target="http://t", recon=lambda _u: [_CHECKOUT], prober=_Prober(),
        gate=_chat_gate("y"), charge_confirmer=lambda f, v: True,
    )
    result = invoker.invoke(get_agent("teller"), request)
    assert result.findings and all(f.status is FindingStatus.REPORTED for f in result.findings)
