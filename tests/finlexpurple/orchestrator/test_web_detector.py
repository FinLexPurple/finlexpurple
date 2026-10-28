"""scan integration: WebDetector detects + verifies and sinks findings.

Uses a fake prober (no network): it returns a SQL-error body whenever a probe
value contains a quote, so the Phase 10 SQLi detector fires and the Phase 11
verifier reproduces it. Confirms the detector (1) reconstructs the endpoint from
the persisted record, (2) runs detection+verification, (3) collects findings in
the sink, and (4) keeps the persisted observation findings-empty.
"""

from __future__ import annotations

from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.detectors.schema import Finding, FindingStatus
from finlexpurple.gates.approval_gate import ApprovalGate
from finlexpurple.orchestrator.executor import Executor, WebDetector

_CHECKOUT = {"method": "GET", "path": "/checkout", "parameter_names": ["price"], "content_type": None}


class _FakeProber:
    """Returns a SQL-error body iff a probe value contains a single quote."""

    def request(self, method, url, *, params=None, headers=None):
        values = " ".join((params or {}).values())
        text = "You have an error in your SQL syntax near ''" if "'" in values else "<html>ok</html>"
        return ProbeResponse(status_code=200, headers={}, text=text)


class _CheckoutProber:
    """A checkout that reflects a submitted price; ``persist`` controls read-back.

    A request carrying a ``price`` param (the tamper probe / replay re-execution)
    reflects it; a param-less GET (the charge_confirmer's in-scope read-back)
    returns the persisted total, which equals the tampered value only when the
    server actually persisted it.
    """

    def __init__(self, *, persist: bool) -> None:
        self._persist = persist

    def request(self, method, url, *, params=None, headers=None):
        params = params or {}
        if "price" in params:
            return ProbeResponse(200, {}, f"total={params['price']}")
        return ProbeResponse(200, {}, f"receipt total={'0.01' if self._persist else '49.99'}")


def _approving_gate() -> ApprovalGate:
    return ApprovalGate(True, interactive=True, confirm_fn=lambda _p: True)


def test_web_detector_sinks_verified_finding_and_persists_empty() -> None:
    sink: list[Finding] = []
    detector = WebDetector(origin="http://t.invalid", prober=_FakeProber(), sink=sink)
    record = {"method": "GET", "path": "/search", "parameter_names": ["q"], "content_type": None}

    observation = detector.run(record)

    # Persisted observation stays findings-empty (privacy guarantee).
    assert observation == {"findings": []}
    # The real findings are collected in the sink, and SQLi was verified by replay.
    sqli = [f for f in sink if f.vulnerability_class == "sqli"]
    assert sqli and sqli[0].status is FindingStatus.VERIFIED
    assert sqli[0].url == "http://t.invalid/search"
    # Per-finding agent attribution (§16): every sunk finding names its agent,
    # and web-detection findings are attributed to the 'hunter' detection agent.
    assert all(f.agent for f in sink)
    assert sqli[0].agent == "hunter"


def test_executor_dispatches_to_injected_web_detector() -> None:
    sink: list[Finding] = []
    executor = Executor({"phase8_stub": WebDetector(origin="http://t.invalid", prober=_FakeProber(), sink=sink)})
    result = executor.execute({
        "action_id": "stub-0000",
        "detector": "phase8_stub",
        "endpoint": {"method": "GET", "path": "/search", "parameter_names": ["q"], "content_type": None},
    })
    assert result == {"action_id": "stub-0000", "findings": []}
    assert any(f.vulnerability_class == "sqli" for f in sink)


def test_scan_verifies_price_tampering_when_charge_confirmed() -> None:
    sink: list[Finding] = []
    prober = _CheckoutProber(persist=True)
    detector = WebDetector(
        origin="http://t.invalid", prober=prober, sink=sink,
        gate=_approving_gate(),
        charge_confirmer=lambda f, v: v in prober.request("GET", f.url).text,
    )
    detector.run(_CHECKOUT)
    pt = [f for f in sink if f.vulnerability_class == "price_tampering"]
    assert pt and pt[0].status is FindingStatus.VERIFIED
    assert pt[0].agent == "cashier"


def test_scan_reports_price_tampering_when_not_persisted() -> None:
    sink: list[Finding] = []
    prober = _CheckoutProber(persist=False)  # reflects but does not persist
    detector = WebDetector(
        origin="http://t.invalid", prober=prober, sink=sink,
        gate=_approving_gate(),
        charge_confirmer=lambda f, v: v in prober.request("GET", f.url).text,
    )
    detector.run(_CHECKOUT)
    pt = [f for f in sink if f.vulnerability_class == "price_tampering"]
    assert pt and pt[0].status is FindingStatus.REPORTED


def test_scan_without_gate_leaves_price_tampering_reported() -> None:
    sink: list[Finding] = []
    detector = WebDetector(origin="http://t.invalid", prober=_CheckoutProber(persist=True), sink=sink)
    detector.run(_CHECKOUT)
    pt = [f for f in sink if f.vulnerability_class == "price_tampering"]
    assert pt and pt[0].status is FindingStatus.REPORTED  # no gate -> never verified
