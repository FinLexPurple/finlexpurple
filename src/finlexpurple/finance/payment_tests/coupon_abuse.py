"""Coupon / discount abuse: a passive candidate check plus active capture (Unit 2.2).

The passive :func:`check` is the read-only surface heuristic (unchanged). The
active mode (a prober injected) applies a **distinctive bogus coupon** — a code
the shop never issued — to a coupon endpoint and, on acceptance, emits a finding
carrying the re-applicable ``param=code`` for a later gated replay. Applying a
coupon mutates the cart, so the replay routes through the approval gate and is
verified only when an in-scope order-status read-back shows the illegitimate
discount durably applied.
"""

from __future__ import annotations

from finlexpurple.detectors.prober import Prober
from finlexpurple.detectors.schema import Finding, Severity
from finlexpurple.finance.payment_tests._common import (
    candidate_finding,
    coupon_apply_finding,
    param_set,
)
from finlexpurple.recon.endpoint_catalog import Endpoint

_PARAMS = {"coupon", "promo", "discount", "voucher", "promocode", "code"}

# The cart order the coupon endpoint operates on, and whose persisted total the
# read-back confirmer inspects. A fixed sentinel known to the CLI, exactly like
# webhook_bypass.FORGED_ORDER_ID — it ties the coupon read-back to the lab target.
CART_ORDER_ID = "ord-1001"

# A distinctive coupon code the shop never issued. If it is accepted and durably
# discounts the order, that is the abuse — and the distinctive value keeps the
# read-back's "code persisted on the order" criterion from matching incidentally.
_SENTINEL_CODE = "FLP-BOGUS-COUPON"


def looks_like_coupon(endpoint: Endpoint) -> bool:
    """True if the endpoint exposes a coupon/discount-like parameter."""

    return bool(_PARAMS & param_set(endpoint))


def check(
    endpoints: list[Endpoint], *, agent: str, prober: Prober | None = None
) -> list[Finding]:
    """Flag coupon endpoints; passively (no prober) or by active capture (prober).

    * **Passive** (no prober) — one prose candidate per endpoint, keyed on
      parameter *names* only (what ``run_all`` uses; the scan path is untouched).
    * **Active** (a prober) — apply the bogus sentinel coupon to each coupon-like
      parameter and, on acceptance, emit a finding carrying the real ``param=code``
      for later deterministic replay. Findings are always ``reported`` — capture
      never verifies.
    """

    findings: list[Finding] = []
    for endpoint in endpoints:
        hits = _PARAMS & param_set(endpoint)
        if not hits:
            continue
        if prober is None:
            findings.append(candidate_finding(
                endpoint, vclass="coupon_abuse",
                reason=f"coupon/discount parameter(s) {sorted(hits)}; verify single-use and stacking limits",
                severity=Severity.MEDIUM, agent=agent,
            ))
            continue
        sent_headers: dict[str, str] = {}
        for param in sorted(hits):
            response = prober.request(
                endpoint.method, endpoint.url,
                params={param: _SENTINEL_CODE}, headers=sent_headers or None,
            )
            if 200 <= response.status_code < 300:
                findings.append(coupon_apply_finding(
                    endpoint, param=param, code=_SENTINEL_CODE,
                    response=response, request_headers=sent_headers,
                    severity=Severity.MEDIUM, agent=agent,
                ))
    return findings
