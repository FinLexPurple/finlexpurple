"""Refund / reversal abuse: a passive candidate check plus active capture (Phase 19a + Unit 2.4).

The passive :func:`check` is the original read-only surface heuristic — it flags any
refund/reversal-family endpoint by path, params or not (what ``run_all`` uses; the
scan path is untouched). The active mode (a prober injected) requests a refund whose
client-supplied ``amount`` exceeds what was paid — on a refund endpoint that has no
amount/idempotency check — and, on acceptance, emits a finding carrying the
re-sendable ``param=amount`` for a later gated replay. The replay is verified only
when an in-scope refund-status read-back shows the order's refunded total durably
**exceeding** the amount paid; because the endpoint is not idempotent, the gated
re-send is itself the duplicate/double-refund corollary.
"""

from __future__ import annotations

from finlexpurple.detectors.prober import Prober
from finlexpurple.detectors.schema import Finding, Severity
from finlexpurple.finance.payment_tests._common import (
    candidate_finding,
    param_set,
    path_of,
    refund_finding,
)
from finlexpurple.recon.endpoint_catalog import Endpoint

# Refund/reversal-family path markers (the original Phase-19a surface heuristic).
_MARKERS = ("refund", "cancel", "reverse", "chargeback")

# Amount-like parameters the active over-refund capture targets.
_PARAMS = {"amount", "refund", "value", "total"}

# The order the refund endpoint refunds, and whose persisted refunded/paid totals
# the read-back confirmer compares. A fixed sentinel known to the CLI, like
# payment_status_trust.STATUS_ORDER_ID — a dedicated paid order so a refund never
# collides with the cart / status mutations.
REFUND_ORDER_ID = "ord-refund-0001"

# The client-set refund amount the capture asserts: deliberately larger than any
# plausible paid amount, so acceptance is an over-refund the read-back can confirm.
# The confirmer decides reproduced by comparing the order's durable refunded total
# against the amount paid — never by trusting this requested value.
_OVER_REFUND_AMOUNT = "999.99"


def _is_refund_path(endpoint: Endpoint) -> bool:
    """True when the endpoint's path is a refund/reversal-family surface."""

    return any(marker in path_of(endpoint) for marker in _MARKERS)


def looks_like_refund(endpoint: Endpoint) -> bool:
    """True for an over-refundABLE endpoint: a refund-family path AND an amount-like param.

    The path check keeps this off endpoints that merely carry an ``amount`` field
    for another purpose (e.g. the Scope-1 checkout, whose ``amount`` is a price, not
    a refund); the param check is what the active capture needs to over-refund.
    """

    return _is_refund_path(endpoint) and bool(_PARAMS & param_set(endpoint))


def check(
    endpoints: list[Endpoint], *, agent: str, prober: Prober | None = None
) -> list[Finding]:
    """Flag refund/reversal endpoints; passively (by path) or by active over-refund capture.

    * **Passive** (no prober) — one prose candidate per refund-family endpoint, keyed
      on the path marker only (the original Phase-19a behaviour ``run_all`` relies on;
      the scan path is untouched).
    * **Active** (a prober) — on a refund-family endpoint that also has an amount-like
      parameter, request a refund of ``_OVER_REFUND_AMOUNT`` on each such parameter
      and, on acceptance, emit a finding carrying the real ``param=amount`` for later
      deterministic replay. Findings are always ``reported`` — capture never verifies.
    """

    findings: list[Finding] = []
    for endpoint in endpoints:
        if not _is_refund_path(endpoint):
            continue
        if prober is None:
            findings.append(candidate_finding(
                endpoint, vclass="refund_abuse",
                reason="refund/reversal endpoint; verify authorization, amount limits, and idempotency",
                severity=Severity.MEDIUM, agent=agent,
            ))
            continue
        hits = _PARAMS & param_set(endpoint)
        if not hits:
            continue  # active capture needs an amount-like param to over-refund
        sent_headers: dict[str, str] = {}
        for param in sorted(hits):
            response = prober.request(
                endpoint.method, endpoint.url,
                params={param: _OVER_REFUND_AMOUNT}, headers=sent_headers or None,
            )
            if 200 <= response.status_code < 300:
                findings.append(refund_finding(
                    endpoint, param=param, amount=_OVER_REFUND_AMOUNT,
                    response=response, request_headers=sent_headers,
                    severity=Severity.HIGH, agent=agent,
                ))
    return findings
