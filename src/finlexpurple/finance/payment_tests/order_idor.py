"""Order / invoice IDOR candidate check (Phase 19a; §7)."""

from __future__ import annotations

from finlexpurple.detectors.schema import Finding, Severity
from finlexpurple.finance.payment_tests._common import candidate_finding, param_set, path_of
from finlexpurple.recon.endpoint_catalog import Endpoint

_PATHS = ("order", "invoice", "receipt")
_ID_PARAMS = {"id", "order_id", "invoice_id", "oid", "ref"}


def check(endpoints: list[Endpoint], *, agent: str) -> list[Finding]:
    """Flag order/invoice endpoints with an id-like parameter (IDOR risk)."""

    findings: list[Finding] = []
    for endpoint in endpoints:
        if any(marker in path_of(endpoint) for marker in _PATHS) and (_ID_PARAMS & param_set(endpoint)):
            findings.append(candidate_finding(
                endpoint, vclass="order_idor",
                reason="order/invoice endpoint keyed by a client id; verify per-object authorization",
                severity=Severity.HIGH, agent=agent,
            ))
    return findings
