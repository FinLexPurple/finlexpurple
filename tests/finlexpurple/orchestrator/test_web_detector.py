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
from finlexpurple.orchestrator.executor import Executor, WebDetector


class _FakeProber:
    """Returns a SQL-error body iff a probe value contains a single quote."""

    def request(self, method, url, *, params=None, headers=None):
        values = " ".join((params or {}).values())
        text = "You have an error in your SQL syntax near ''" if "'" in values else "<html>ok</html>"
        return ProbeResponse(status_code=200, headers={}, text=text)


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
