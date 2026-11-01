"""Unit 3: the shared gated capture+verify helper (scan and isolation share it).

Proves the helper reaches VERIFIED for a standard-gate agent when config-allowed,
and that a hard-gated category (teller/vault) can never be config-allowed, so it
sends no active probe and never verifies — the invariant, exercised in the exact
code path an isolated specialist run uses.
"""

from __future__ import annotations

from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.detectors.schema import FindingStatus
from finlexpurple.finance.payment_tests import financial_specialist as fs
from finlexpurple.gates.approval_gate import ApprovalGate
from finlexpurple.recon.endpoint_catalog import Endpoint

_CHECKOUT = Endpoint(method="GET", url="http://t/checkout", parameters=("price",), content_type=None)


class _Prober:
    def __init__(self) -> None:
        self.sent: list[tuple] = []

    def request(self, method, url, *, params=None, headers=None, body=None) -> ProbeResponse:
        self.sent.append((method, url, params or {}, body))
        return ProbeResponse(200, {}, f"total={(params or {}).get('price', '')}")


def _config_allow() -> ApprovalGate:
    # Standard gate with approval disabled: config-allows a non-hard-gated category.
    return ApprovalGate(False, interactive=False)


def test_cashier_config_allow_actively_verifies_price_tampering() -> None:
    prober = _Prober()
    findings = fs.capture_and_verify(
        _CHECKOUT, agent="cashier", prober=prober, gate=_config_allow(), charge_confirmer=lambda f, v: True
    )
    pt = [f for f in findings if f.vulnerability_class == "price_tampering"]
    assert pt and pt[0].status is FindingStatus.VERIFIED
    assert prober.sent  # the tamper probe was actually sent (active)


def test_teller_is_hard_gated_sends_no_probe_and_never_verifies() -> None:
    prober = _Prober()
    findings = fs.capture_and_verify(
        _CHECKOUT, agent="teller", prober=prober, gate=_config_allow(), charge_confirmer=lambda f, v: True
    )
    assert prober.sent == []  # hard-gated: config-allow cannot run it -> no active probe
    assert findings and all(f.status is FindingStatus.REPORTED for f in findings)


def test_vault_is_hard_gated_sends_no_probe_and_never_verifies() -> None:
    prober = _Prober()
    findings = fs.capture_and_verify(
        _CHECKOUT, agent="vault", prober=prober, gate=_config_allow(), charge_confirmer=lambda f, v: True
    )
    assert prober.sent == []
    assert findings and all(f.status is FindingStatus.REPORTED for f in findings)


def test_no_gate_leaves_passive_candidates() -> None:
    prober = _Prober()
    findings = fs.capture_and_verify(_CHECKOUT, agent="cashier", prober=prober, gate=None)
    assert prober.sent == []  # no gate -> no active probe
    assert findings and all(f.status is FindingStatus.REPORTED for f in findings)
