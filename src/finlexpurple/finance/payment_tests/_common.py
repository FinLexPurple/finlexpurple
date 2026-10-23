"""Shared helpers for the payment-test checks (Phase 19a).

Each check is a conservative, **read-only surface heuristic**: it inspects the
recon'd endpoints and flags candidate payment-logic weaknesses as ``reported``
findings. It never exploits anything — actual verification of a financial class
is human-gated and awaits the deterministic-replay decision (decisions.md §18
item 5). This keeps banking testing read-only and never auto-exploits a target.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from finlexpurple.detectors.schema import Finding, Severity
from finlexpurple.recon.endpoint_catalog import Endpoint


def path_of(endpoint: Endpoint) -> str:
    """The lowercased URL path of an endpoint."""

    return (urlsplit(endpoint.url).path or "/").lower()


def param_set(endpoint: Endpoint) -> set[str]:
    """The endpoint's parameter names, lowercased."""

    return {p.lower() for p in endpoint.parameters}


def candidate_finding(
    endpoint: Endpoint, *, vclass: str, reason: str, severity: Severity, agent: str
) -> Finding:
    """Build a ``reported`` candidate finding (never an exploited one)."""

    return Finding.new(
        vulnerability_class=vclass,
        method=endpoint.method,
        url=endpoint.url,
        payload=f"{vclass}:{reason}",
        expected_signal=(
            f"{reason}. Reported candidate only — verification is read-only and human-gated, "
            "never auto-exploited."
        ),
        severity=severity,
        agent=agent,
    )
