"""Price-tampering candidate check (Phase 19a; §7)."""

from __future__ import annotations

from finlexpurple.detectors.prober import Prober
from finlexpurple.detectors.schema import Finding, Severity
from finlexpurple.finance.payment_tests._common import (
    candidate_finding,
    param_set,
    tampered_finding,
)
from finlexpurple.recon.endpoint_catalog import Endpoint

_PRICE_PARAMS = {"price", "amount", "total", "cost", "subtotal", "grandtotal"}

# A deliberately low, distinctive sentinel price used for the tamper probe. A low
# value is the classic price-tamper manipulation; a distinctive one keeps the
# "tampered value reflected in the response" criterion (checked by a later
# deterministic replay) from being swamped by incidental matches — a bare "1"
# appears in almost any page, whereas an exact "0.01" reflected back is signal.
_TAMPER_VALUE = "0.01"


def check(
    endpoints: list[Endpoint], *, agent: str, prober: Prober | None = None
) -> list[Finding]:
    """Flag endpoints exposing a client-controllable price-like parameter.

    Two modes, by whether a ``prober`` is injected:

    * **Passive** (no prober) — unchanged behaviour: one prose candidate per
      endpoint, keyed on parameter *names* only. This is what ``run_all`` uses
      today, so the scan path is untouched by this change.
    * **Active** (a prober is injected) — send one tampered request per
      price-like parameter and, when the tampered value is reflected in the
      response, emit a finding carrying the real ``param=value`` payload,
      request headers, and ``response_snapshot`` for later deterministic replay.
      Every request routes through the prober, which enforces default-deny
      egress, the per-target budget, and rate limiting before any socket opens;
      the check adds no concurrency and sends one request per parameter.

    Findings are always created ``reported`` — this check captures evidence and
    never verifies, so observing a reflection here does not mark anything
    ``verified``.
    """

    findings: list[Finding] = []
    for endpoint in endpoints:
        hits = _PRICE_PARAMS & param_set(endpoint)
        if not hits:
            continue
        if prober is None:
            findings.append(candidate_finding(
                endpoint, vclass="price_tampering",
                reason=f"price-like parameter(s) {sorted(hits)} may be client-controlled",
                severity=Severity.HIGH, agent=agent,
            ))
            continue
        sent_headers: dict[str, str] = {}
        for param in sorted(hits):
            response = prober.request(
                endpoint.method, endpoint.url,
                params={param: _TAMPER_VALUE}, headers=sent_headers or None,
            )
            if _TAMPER_VALUE in response.text:
                findings.append(tampered_finding(
                    endpoint, param=param, tampered_value=_TAMPER_VALUE,
                    response=response, request_headers=sent_headers,
                    severity=Severity.HIGH, agent=agent,
                ))
    return findings
