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


def coupon_apply_finding(
    endpoint: Endpoint,
    *,
    param: str,
    code: str,
    response: ProbeResponse,
    request_headers: dict[str, str],
    severity: Severity,
    agent: str,
) -> Finding:
    """Build a ``reported`` coupon_abuse finding carrying a re-applicable coupon request.

    The coupon case applies a client-supplied code to a cart/checkout endpoint, so
    this records the concrete request that was sent — a real ``param=code``
    ``payload`` (the applied coupon) and the ``request_headers`` as sent — plus the
    server's ``response_snapshot``. That is the evidence a later deterministic
    replay re-applies.

    ``expected_signal`` states, in a code-checkable way, the criterion the replay
    will test: the bogus coupon was accepted and (the decisive step) the discount
    is durably reflected on the order via an in-scope order-status read-back.
    Acceptance alone is a necessary, not sufficient, proof — the replay owns the
    full pass/fail — so the status stays ``reported`` here; capture never verifies.
    """

    return Finding.new(
        vulnerability_class="coupon_abuse",
        method=endpoint.method,
        url=endpoint.url,
        payload=f"{param}={code}",
        headers=dict(request_headers),
        body=None,
        response_snapshot=response.text[:_SNAPSHOT_MAX_CHARS],
        expected_signal=(
            f"server accepted a client-supplied coupon {code!r} it never issued; reproduced only "
            "if an in-scope order-status read-back shows the illegitimate discount durably applied"
        ),
        severity=severity,
        agent=agent,
    )


def status_set_finding(
    endpoint: Endpoint,
    *,
    param: str,
    status: str,
    response: ProbeResponse,
    request_headers: dict[str, str],
    severity: Severity,
    agent: str,
) -> Finding:
    """Build a ``reported`` payment_status_trust finding carrying a re-sendable status set.

    The payment-status case sets a client-controllable status field (e.g.
    ``status=paid``) on an order endpoint, so this records the concrete request
    that was sent — a real ``param=status`` ``payload`` and the ``request_headers``
    as sent — plus the server's ``response_snapshot``. That is the evidence a later
    deterministic replay re-sends.

    ``expected_signal`` states, in a code-checkable way, the criterion the replay
    will test: the client-set status was accepted and (the decisive step) the order
    is durably marked with it via an in-scope order-status read-back, without any
    real settlement. Acceptance alone is a necessary, not sufficient, proof — the
    replay owns the full pass/fail — so the status stays ``reported`` here.
    """

    return Finding.new(
        vulnerability_class="payment_status_trust",
        method=endpoint.method,
        url=endpoint.url,
        payload=f"{param}={status}",
        headers=dict(request_headers),
        body=None,
        response_snapshot=response.text[:_SNAPSHOT_MAX_CHARS],
        expected_signal=(
            f"server accepted a client-set payment status {status!r}; reproduced only if an "
            "in-scope order-status read-back shows the order durably marked with it without settlement"
        ),
        severity=severity,
        agent=agent,
    )


def refund_finding(
    endpoint: Endpoint,
    *,
    param: str,
    amount: str,
    response: ProbeResponse,
    request_headers: dict[str, str],
    severity: Severity,
    agent: str,
) -> Finding:
    """Build a ``reported`` refund_abuse finding carrying a re-sendable over-refund.

    The refund case requests a refund whose client-supplied ``amount`` exceeds what
    was paid (no amount/idempotency check on the endpoint), so this records the
    concrete request that was sent — a real ``param=amount`` ``payload`` (the
    requested refund) and the ``request_headers`` as sent — plus the server's
    ``response_snapshot``. That is the evidence a later deterministic replay
    re-sends; because the endpoint has no idempotency key, re-sending also
    demonstrates the duplicate/double-refund corollary.

    ``expected_signal`` states, in a code-checkable way, the criterion the replay
    will test: the refund was accepted and (the decisive step) an in-scope
    refund-status read-back shows the order's refunded total durably **exceeding**
    the amount paid. Acceptance alone is a necessary, not sufficient, proof — the
    replay owns the full pass/fail — so the status stays ``reported`` here; capture
    never verifies.
    """

    return Finding.new(
        vulnerability_class="refund_abuse",
        method=endpoint.method,
        url=endpoint.url,
        payload=f"{param}={amount}",
        headers=dict(request_headers),
        body=None,
        response_snapshot=response.text[:_SNAPSHOT_MAX_CHARS],
        expected_signal=(
            f"server accepted a client-supplied refund {param}={amount!r} with no amount/idempotency "
            "check; reproduced only if an in-scope refund-status read-back shows the order's refunded "
            "total durably exceeding the amount paid"
        ),
        severity=severity,
        agent=agent,
    )


def forged_callback_finding(
    endpoint: Endpoint,
    *,
    descriptor: str,
    forged_body: str,
    request_headers: dict[str, str],
    response: ProbeResponse,
    severity: Severity,
    agent: str,
) -> Finding:
    """Build a ``reported`` webhook_bypass finding carrying a re-executable forged callback.

    The webhook case is a **POST with a body**, not a query-parameter tamper, so
    this is the body-carrying counterpart to :func:`tampered_finding`. It records
    the concrete forged request that was actually sent — the request ``body`` (the
    forged JSON callback) and the ``request_headers`` as sent (including the
    deliberately invalid/absent signature) — plus the server's
    ``response_snapshot``. That is the evidence a later deterministic replay
    re-sends. ``payload`` is a concrete descriptor of the forgery (so the
    deterministic ``finding_id`` is stable per endpoint), while the exact bytes to
    re-send live in ``body``.

    ``expected_signal`` states, in a code-checkable way, the criterion the replay
    will test: the server accepted the unsigned/invalid-signature callback and
    (the decisive step) the order was durably marked paid. Acceptance alone is a
    necessary, not sufficient, proof — the replay owns the full pass/fail — so the
    status stays ``reported`` here; capture never verifies.
    """

    return Finding.new(
        vulnerability_class="webhook_bypass",
        method=endpoint.method,
        url=endpoint.url,
        payload=f"webhook_bypass:{descriptor}",
        headers=dict(request_headers),
        body=forged_body,
        response_snapshot=response.text[:_SNAPSHOT_MAX_CHARS],
        expected_signal=(
            "server accepted an unsigned/invalid-signature 'paid' callback (HTTP 2xx); "
            "reproduced only if an in-scope read-back confirms the order durably flipped to paid"
        ),
        severity=severity,
        agent=agent,
    )
