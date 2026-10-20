"""SQL-injection detector (Phase 10; decisions.md §6).

Sends a single-quote payload into each parameter and flags the endpoint if the
response contains a known SQL-error signature. The payload is fixed (not random)
so the resulting ``finding_id`` is deterministic across re-runs. Detection only
produces a ``reported`` finding; Phase 11's replay engine is what promotes it to
``verified``.
"""

from __future__ import annotations

from finlexpurple.detectors.prober import Prober
from finlexpurple.detectors.schema import Finding, Severity
from finlexpurple.recon.endpoint_catalog import Endpoint

AGENT = "hunter"
_PAYLOAD = "'"
_SQL_ERROR_SIGNS = (
    "sql syntax",
    "you have an error in your sql",
    "warning: mysql",
    "mysql_fetch",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "ora-0",
    "sqlite3.",
    "sqlite error",
    "psycopg2.",
    "pg::syntaxerror",
    "sqlstate",
    "syntax error at or near",
)


def detect(endpoint: Endpoint, prober: Prober) -> list[Finding]:
    """Return a finding per parameter whose response reveals a SQL error."""

    findings: list[Finding] = []
    for param in endpoint.parameters:
        response = prober.request(endpoint.method, endpoint.url, params={param: _PAYLOAD})
        lowered = response.text.lower()
        if any(sign in lowered for sign in _SQL_ERROR_SIGNS):
            findings.append(
                Finding.new(
                    vulnerability_class="sqli",
                    method=endpoint.method,
                    url=endpoint.url,
                    payload=f"{param}={_PAYLOAD}",
                    response_snapshot=response.text[:2000],
                    expected_signal="SQL error string in response after a single-quote payload",
                    severity=Severity.HIGH,
                    agent=AGENT,
                )
            )
    return findings
