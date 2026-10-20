"""Fingerprint/shape-driven detector dispatch (Phase 10; decisions.md §6).

Decides which detectors are worth running against a given endpoint, so the scan
does not waste requests — e.g. parameter-based detectors (SQLi, XSS, IDOR) are
skipped on a static, parameterless endpoint, and SSRF runs only when a parameter
looks URL-shaped. Header/response-based detectors (generic/auth misconfig,
cache poisoning) always run. The fingerprint is accepted for future
technology-specific narrowing; current relevance is driven by endpoint shape.
"""

from __future__ import annotations

from collections.abc import Callable

from finlexpurple.detectors import (
    auth_misconfig,
    cache_poisoning,
    generic_misconfig,
    idor,
    sqli,
    ssrf,
    xss,
)
from finlexpurple.detectors.prober import Prober
from finlexpurple.detectors.schema import Finding
from finlexpurple.recon.endpoint_catalog import Endpoint
from finlexpurple.recon.fingerprint import Fingerprint

Detector = Callable[[Endpoint, Prober], list[Finding]]


def relevant_detectors(endpoint: Endpoint, fingerprint: Fingerprint | None = None) -> list[Detector]:
    """Return the detectors worth running against ``endpoint``, by its shape."""

    del fingerprint  # reserved for technology-specific narrowing later
    detectors: list[Detector] = []
    if endpoint.parameters:
        detectors.append(sqli.detect)
        detectors.append(xss.detect)
        if any(idor.looks_like_id_param(p) for p in endpoint.parameters):
            detectors.append(idor.detect)
        if any(ssrf.accepts_url_param(p) for p in endpoint.parameters):
            detectors.append(ssrf.detect)
    # Response/header-based checks apply to every endpoint.
    detectors.append(generic_misconfig.detect)
    detectors.append(auth_misconfig.detect)
    detectors.append(cache_poisoning.detect)
    return detectors


def run_relevant(
    endpoint: Endpoint, prober: Prober, fingerprint: Fingerprint | None = None
) -> list[Finding]:
    """Run every relevant detector against ``endpoint`` and aggregate the findings."""

    findings: list[Finding] = []
    for detector in relevant_detectors(endpoint, fingerprint):
        findings.extend(detector(endpoint, prober))
    return findings
