"""Shared helpers for the payment-test checks (Phase 19a).

Each check is a conservative, **read-only surface heuristic**: it inspects the
recon'd endpoints and flags candidate payment-logic weaknesses as ``reported``
findings. It never exploits anything — actual verification of a financial class
is human-gated and awaits the deterministic-replay decision (decisions.md §18
item 5). This keeps banking testing read-only and never auto-exploits a target.
"""

from __future__ import annotations

from urllib.parse import urlsplit

from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.detectors.schema import Finding, Severity
from finlexpurple.recon.endpoint_catalog import Endpoint

# Captured response bodies are truncated to this many characters — the same
# convention the web detectors use (see detectors/sqli.py, which stores
# ``response.text[:2000]``). Integrity of the full pair is covered separately by
# ``Finding.evidence_hash`` (schema.py), so this truncation is for readability
# only, not a security boundary.
_SNAPSHOT_MAX_CHARS = 2000


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


def tampered_finding(
    endpoint: Endpoint,
    *,
    param: str,
    tampered_value: str,
    response: ProbeResponse,
    request_headers: dict[str, str],
    severity: Severity,
    agent: str,
) -> Finding:
    """Build a ``reported`` price-tampering finding carrying a re-executable request.

    This is the active-capture counterpart to :func:`candidate_finding`. Where
    ``candidate_finding`` is a passive, prose-only surface flag, this records the
    concrete request that was actually sent — a real ``param=value`` ``payload``
    (not a prose label), the ``request_headers`` as sent, and ``body`` ``None``
    for a query-parameter tamper — together with the server's
    ``response_snapshot``. That is the evidence a later deterministic replay
    re-executes.

    ``expected_signal`` states, in a code-checkable way, the criterion that
    replay will test: the ``tampered_value`` reflected back in the response body,
    i.e. the server appears to accept a client-controlled price. Reflection is a
    necessary, not sufficient, proof — the deterministic replay owns the full
    pass/fail — so the status stays ``reported`` here; capture never verifies.
    """

    return Finding.new(
        vulnerability_class="price_tampering",
        method=endpoint.method,
        url=endpoint.url,
        payload=f"{param}={tampered_value}",
        headers=dict(request_headers),
        body=None,
        response_snapshot=response.text[:_SNAPSHOT_MAX_CHARS],
        expected_signal=(
            f"tampered value {tampered_value!r} reflected in the response body "
            f"(server appears to accept a client-controlled {param!r} price)"
        ),
        severity=severity,
        agent=agent,
    )
