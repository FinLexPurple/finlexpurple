"""IDOR detector (Phase 10; decisions.md §6).

A conservative detection heuristic: for an id-like parameter, request two
different id values and flag the endpoint if both return 200 with substantively
different, non-empty bodies — a candidate insecure direct object reference. The
payload is fixed, so ``finding_id`` is deterministic. This is detection only
(``reported``); Phase 11's two-session diff is what confirms genuine
unauthorized access.
"""

from __future__ import annotations

import re

from finlexpurple.detectors.prober import Prober
from finlexpurple.detectors.schema import Finding, Severity
from finlexpurple.recon.endpoint_catalog import Endpoint

AGENT = "hunter"
_ID_NAME = re.compile(
    r"(?:^|[_-])(?:id|uid|user(?:id)?|account|order|invoice|doc|record|item|profile)(?:[_-]?id)?$",
    re.IGNORECASE,
)


def looks_like_id_param(name: str) -> bool:
    """True if a parameter name looks like a direct object identifier."""

    return name.strip().lower() == "id" or bool(_ID_NAME.search(name))


def detect(endpoint: Endpoint, prober: Prober) -> list[Finding]:
    """Return a finding per id-like parameter that returns differing 200 bodies."""

    findings: list[Finding] = []
    for param in endpoint.parameters:
        if not looks_like_id_param(param):
            continue
        first = prober.request(endpoint.method, endpoint.url, params={param: "1"})
        second = prober.request(endpoint.method, endpoint.url, params={param: "2"})
        if (
            first.status_code == 200
            and second.status_code == 200
            and first.text.strip()
            and first.text != second.text
        ):
            findings.append(
                Finding.new(
                    vulnerability_class="idor",
                    method=endpoint.method,
                    url=endpoint.url,
                    payload=f"{param}=1|2",
                    response_snapshot=(first.text[:1000] + "\n---\n" + second.text[:1000]),
                    expected_signal="id parameter returns differing 200 bodies for different ids "
                    "(candidate insecure direct object reference)",
                    severity=Severity.MEDIUM,
                    agent=AGENT,
                )
            )
    return findings
