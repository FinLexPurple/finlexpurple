"""Client-trusted payment status: a passive candidate check plus active capture (Unit 2.3).

The passive :func:`check` is the read-only surface heuristic (unchanged). The
active mode (a prober injected) sets a client-controlled status (``status=paid``)
on the order's **own** status endpoint — distinct from the webhook callback path —
and, on acceptance, emits a finding carrying the re-sendable ``param=status`` for a
later gated replay. The replay is verified only when an in-scope order-status
read-back shows the order durably marked with the client-set status, without any
real settlement.
"""

from __future__ import annotations

from finlexpurple.detectors.prober import Prober
from finlexpurple.detectors.schema import Finding, Severity
from finlexpurple.finance.payment_tests._common import (
    candidate_finding,
    param_set,
    path_of,
    status_set_finding,
)
from finlexpurple.recon.endpoint_catalog import Endpoint

_PARAMS = {"status", "paid", "payment_status", "state", "success"}

# The order whose status the endpoint sets, and whose persisted status the
# read-back confirmer inspects. A fixed sentinel known to the CLI, like
# webhook_bypass.FORGED_ORDER_ID — a dedicated order so it never collides with the
# cart (price/coupon) mutations.
STATUS_ORDER_ID = "ord-status-0001"

# The client-set status the capture asserts. Reused by the read-back confirmer to
# check the order was durably marked with it.
_PAID_STATUS = "paid"


def looks_like_status(endpoint: Endpoint) -> bool:
    """True for a status-SETTING endpoint: a status-like param AND a status-y path.

    The path check keeps this off endpoints that merely carry a ``status`` field
    for another purpose (e.g. the Scope-2 webhook callback, whose body has
    ``status`` but whose path is not a status mutation).
    """

    return bool(_PARAMS & param_set(endpoint)) and "status" in path_of(endpoint)


def check(
    endpoints: list[Endpoint], *, agent: str, prober: Prober | None = None
) -> list[Finding]:
    """Flag client-trusted payment-status endpoints; passively or by active capture.

    * **Passive** (no prober) — one prose candidate per endpoint, keyed on
      parameter *names* only (what ``run_all`` uses; the scan path is untouched).
    * **Active** (a prober) — set ``status=paid`` on each status-like parameter of a
      status-setting endpoint and, on acceptance, emit a finding carrying the real
      ``param=status`` for later deterministic replay. Findings are always
      ``reported`` — capture never verifies.
    """

    findings: list[Finding] = []
    for endpoint in endpoints:
        hits = _PARAMS & param_set(endpoint)
        if not hits:
            continue
        if prober is None:
            findings.append(candidate_finding(
                endpoint, vclass="payment_status_trust",
                reason=f"payment-status parameter(s) {sorted(hits)} may be trusted from the client",
                severity=Severity.HIGH, agent=agent,
            ))
            continue
        if "status" not in path_of(endpoint):
            continue  # active capture only targets a status-SETTING endpoint
        sent_headers: dict[str, str] = {}
        for param in sorted(hits):
            response = prober.request(
                endpoint.method, endpoint.url,
                params={param: _PAID_STATUS}, headers=sent_headers or None,
            )
            if 200 <= response.status_code < 300:
                findings.append(status_set_finding(
                    endpoint, param=param, status=_PAID_STATUS,
                    response=response, request_headers=sent_headers,
                    severity=Severity.HIGH, agent=agent,
                ))
    return findings
