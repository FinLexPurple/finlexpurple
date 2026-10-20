"""Cache-poisoning detector (Phase 10; decisions.md §6).

Sends an unkeyed request header (``X-Forwarded-Host``) carrying a marker and
flags the endpoint if the marker is reflected into the response body — a
candidate cache-poisoning primitive (an unkeyed input influencing a cacheable
response). Detection only (``reported``); Phase 11 confirms via a cache-state
hash diff. Payload is fixed, so the finding is deterministic.
"""

from __future__ import annotations

from finlexpurple.detectors.prober import Prober
from finlexpurple.detectors.schema import Finding, Severity
from finlexpurple.recon.endpoint_catalog import Endpoint

AGENT = "hunter"
_MARKER = "flpcache-poison-marker"


def detect(endpoint: Endpoint, prober: Prober) -> list[Finding]:
    """Return a candidate finding if an unkeyed header is reflected in the response."""

    response = prober.request(
        endpoint.method, endpoint.url, headers={"X-Forwarded-Host": _MARKER}
    )
    if _MARKER not in response.text:
        return []
    return [
        Finding.new(
            vulnerability_class="cache_poisoning",
            method=endpoint.method,
            url=endpoint.url,
            payload="X-Forwarded-Host: " + _MARKER,
            response_snapshot=response.text[:2000],
            expected_signal="unkeyed X-Forwarded-Host reflected into the response body "
            "(candidate cache poisoning; confirm via cache-state diff in Phase 11)",
            severity=Severity.MEDIUM,
            agent=AGENT,
        )
    ]
