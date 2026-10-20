"""Reflected-XSS detector (Phase 10; decisions.md §6).

Injects a deterministic marker into each parameter and flags the endpoint if the
marker is reflected **unescaped** in an HTML response (the raw ``<marker>``
appears verbatim). The marker is derived from the parameter name (not random),
so ``finding_id`` is deterministic. This is detection only (``reported``);
Phase 11 confirms real DOM execution in a headless browser.
"""

from __future__ import annotations

from finlexpurple.detectors.prober import Prober
from finlexpurple.detectors.schema import Finding, Severity
from finlexpurple.recon.endpoint_catalog import Endpoint

AGENT = "hunter"


def _marker(param: str) -> str:
    # Deterministic per parameter so the finding id is stable across runs.
    safe = "".join(ch for ch in param if ch.isalnum()) or "p"
    return f"<flpxss-{safe}>"


def detect(endpoint: Endpoint, prober: Prober) -> list[Finding]:
    """Return a finding per parameter whose marker is reflected unescaped in HTML."""

    findings: list[Finding] = []
    for param in endpoint.parameters:
        marker = _marker(param)
        response = prober.request(endpoint.method, endpoint.url, params={param: marker})
        content_type = response.headers.get("content-type", "").lower()
        if "html" in content_type and marker in response.text:
            findings.append(
                Finding.new(
                    vulnerability_class="xss",
                    method=endpoint.method,
                    url=endpoint.url,
                    payload=f"{param}={marker}",
                    response_snapshot=response.text[:2000],
                    expected_signal="injected marker reflected unescaped in an HTML response",
                    severity=Severity.HIGH,
                    agent=AGENT,
                )
            )
    return findings
