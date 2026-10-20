"""Authentication/session misconfiguration detector (Phase 10; decisions.md §6).

A concrete, deterministic check: if the endpoint sets a cookie without the
``Secure`` and/or ``HttpOnly`` flags, flag it as a session/auth misconfiguration.
Detection only (``reported``). Payload is fixed, so the finding is deterministic.
"""

from __future__ import annotations

from finlexpurple.detectors.prober import Prober
from finlexpurple.detectors.schema import Finding, Severity
from finlexpurple.recon.endpoint_catalog import Endpoint

AGENT = "hunter"


def detect(endpoint: Endpoint, prober: Prober) -> list[Finding]:
    """Return a finding if a Set-Cookie response is missing Secure/HttpOnly."""

    response = prober.request(endpoint.method, endpoint.url)
    cookie = response.headers.get("set-cookie", "")
    if not cookie:
        return []
    lowered = cookie.lower()
    missing = [flag for flag in ("secure", "httponly") if flag not in lowered]
    if not missing:
        return []
    return [
        Finding.new(
            vulnerability_class="auth_misconfig",
            method=endpoint.method,
            url=endpoint.url,
            payload="set-cookie-missing:" + ",".join(missing),
            expected_signal=f"Set-Cookie missing flag(s): {', '.join(missing)}",
            severity=Severity.MEDIUM,
            agent=AGENT,
        )
    ]
