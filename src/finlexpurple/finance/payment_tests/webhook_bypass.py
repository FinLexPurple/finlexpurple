"""Webhook signature-bypass / replay check (Phase 19a; Unit 2; §7).

Two modes, by whether a ``prober`` is injected:

* **Passive** (no prober) — unchanged: one prose candidate per webhook/callback
  endpoint, keyed on the path only. This is what ``run_all`` uses, so the passive
  scan path is untouched.
* **Active** (a prober is injected) — forge an **unsigned / invalid-signature**
  "paid" callback (a POST body) to the webhook endpoint and, when the server
  appears to accept it (HTTP 2xx), capture a REPLAYABLE finding carrying the
  concrete forged request (method, url, body/headers as sent, response_snapshot)
  and a code-checkable expected_signal. Status stays ``reported`` at capture —
  acceptance is necessary but not sufficient; only a later deterministic replay,
  behind the approval gate and confirmed by an in-scope paid-state read-back, may
  mark it reproduced.

Forging a callback is a state-changing write, so in the scan path it only runs
on a webhook-like endpoint and only behind the approval gate (see
``orchestrator.executor``). A Teller/Vault-origin finding is hard-gated by the
finding's own agent and can never auto-run.
"""

from __future__ import annotations

import json

from finlexpurple.detectors.prober import Prober, ProbeResponse
from finlexpurple.detectors.schema import Finding, Severity
from finlexpurple.finance.payment_tests._common import (
    candidate_finding,
    forged_callback_finding,
    path_of,
)
from finlexpurple.recon.endpoint_catalog import Endpoint

_MARKERS = ("webhook", "callback", "/ipn", "notify")

# A distinctive sentinel order the forgery claims is paid. Distinctive so an
# in-scope read-back for this exact id is signal, not an incidental match; and so
# the probe never touches a real order. "paid" is the durable marker a confirmer
# looks for. These are deliberately public (confirmers import them).
FORGED_ORDER_ID = "flp-webhook-probe-0001"
PAID_MARKER = "paid"

# The forged callback body: a "payment succeeded / paid" event for the sentinel
# order, serialized deterministically (sorted keys -> a stable finding_id).
_FORGED_BODY = json.dumps(
    {"event": "payment_intent.succeeded", "order_id": FORGED_ORDER_ID,
     "status": PAID_MARKER, "amount": "0.00"},
    sort_keys=True,
)
# Deliberately invalid signature: this is exactly what a correctly-implemented
# webhook must reject. A server that accepts it is not validating signatures.
_FORGED_HEADERS = {"Content-Type": "application/json", "X-Signature": "invalid-not-a-real-hmac"}
_DESCRIPTOR = f"forged-paid-callback:{FORGED_ORDER_ID}"


def looks_like_webhook(endpoint: Endpoint) -> bool:
    """True if the endpoint path looks like a payment webhook/callback/IPN/notify."""

    return any(marker in path_of(endpoint) for marker in _MARKERS)


def _accepted(response: ProbeResponse) -> bool:
    """The server appears to accept the callback: a 2xx status."""

    return 200 <= response.status_code < 300


def check(
    endpoints: list[Endpoint], *, agent: str, prober: Prober | None = None
) -> list[Finding]:
    """Flag payment webhook endpoints; actively capture a forged-callback finding when a prober is given."""

    findings: list[Finding] = []
    for endpoint in endpoints:
        if not looks_like_webhook(endpoint):
            continue
        if prober is None:
            findings.append(candidate_finding(
                endpoint, vclass="webhook_bypass",
                reason="payment webhook/callback endpoint; verify signature validation and replay protection",
                severity=Severity.HIGH, agent=agent,
            ))
            continue
        # Active: forge an unsigned 'paid' callback (POST body) and see if it is accepted.
        response = prober.request(
            endpoint.method, endpoint.url,
            headers=dict(_FORGED_HEADERS), body=_FORGED_BODY,
        )
        if _accepted(response):
            findings.append(forged_callback_finding(
                endpoint, descriptor=_DESCRIPTOR, forged_body=_FORGED_BODY,
                request_headers=_FORGED_HEADERS, response=response,
                severity=Severity.HIGH, agent=agent,
            ))
    return findings
