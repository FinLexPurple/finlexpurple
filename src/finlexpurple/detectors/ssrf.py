"""SSRF detector (Phase 10; decisions.md §6).

A conservative surface detector: flags any parameter whose name indicates it
accepts a URL (``url``, ``uri``, ``callback``, ``webhook``, …) as an SSRF
candidate. This is detection only (``reported``) — true SSRF is confirmed in
Phase 11 with an out-of-band canary, never guessed here. No request is sent, so
the finding is deterministic.
"""

from __future__ import annotations

import re

from finlexpurple.detectors.prober import Prober
from finlexpurple.detectors.schema import Finding, Severity
from finlexpurple.recon.endpoint_catalog import Endpoint

AGENT = "hunter"
_URL_PARAM = re.compile(
    r"url|uri|link|dest|redirect|callback|webhook|target|fetch|proxy|feed|src|site|domain|endpoint",
    re.IGNORECASE,
)


def accepts_url_param(name: str) -> bool:
    """True if a parameter name suggests it takes a URL (an SSRF candidate surface)."""

    return bool(_URL_PARAM.search(name))


def detect(endpoint: Endpoint, prober: Prober) -> list[Finding]:
    """Return a candidate SSRF finding for each URL-accepting parameter."""

    del prober  # surface heuristic; Phase 11 confirms out-of-band
    findings: list[Finding] = []
    for param in endpoint.parameters:
        if not accepts_url_param(param):
            continue
        findings.append(
            Finding.new(
                vulnerability_class="ssrf",
                method=endpoint.method,
                url=endpoint.url,
                payload=f"{param}=<attacker-controlled-url>",
                expected_signal="parameter accepts a URL (candidate SSRF surface; "
                "confirm out-of-band in Phase 11)",
                severity=Severity.MEDIUM,
                agent=AGENT,
            )
        )
    return findings
