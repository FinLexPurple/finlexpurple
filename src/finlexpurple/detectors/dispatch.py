"""Fingerprint/shape-driven detector dispatch (Phase 10; decisions.md §6).

Decides which detectors are worth running against a given endpoint, so the scan
does not waste requests — e.g. parameter-based detectors (SQLi, XSS, IDOR) are
skipped on a static, parameterless endpoint, and SSRF runs only when a parameter
looks URL-shaped. Header/response-based detectors (generic/auth misconfig,
cache poisoning) always run. The fingerprint is accepted for future
technology-specific narrowing; current relevance is driven by endpoint shape.

Since Unit 1.6 the relevance rules and the detector callables are read from the
one capability registry (:mod:`finlexpurple.capabilities`) rather than being
hand-maintained here, so a new class is added by one registry record — with no
edit to this module.
"""

from __future__ import annotations

from collections.abc import Callable

from finlexpurple import capabilities
from finlexpurple.detectors.prober import Prober
from finlexpurple.detectors.schema import Finding
from finlexpurple.recon.endpoint_catalog import Endpoint
from finlexpurple.recon.fingerprint import Fingerprint

Detector = Callable[[Endpoint, Prober], list[Finding]]


def relevant_detectors(endpoint: Endpoint, fingerprint: Fingerprint | None = None) -> list[Detector]:
    """Return the detectors worth running against ``endpoint``, by its shape."""

    del fingerprint  # reserved for technology-specific narrowing later
    detectors: list[Detector] = []
    for capability in capabilities.web_capabilities_for(endpoint):
        assert capability.detector is not None  # web_capabilities_for guarantees this
        detectors.append(capability.detector)
    return detectors


def run_relevant(
    endpoint: Endpoint, prober: Prober, fingerprint: Fingerprint | None = None
) -> list[Finding]:
    """Run every relevant detector against ``endpoint`` and aggregate the findings."""

    findings: list[Finding] = []
    for detector in relevant_detectors(endpoint, fingerprint):
        findings.extend(detector(endpoint, prober))
    return findings
