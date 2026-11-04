"""Order / invoice IDOR: a passive candidate check plus active two-session capture.

The passive :func:`check` is the read-only surface heuristic (unchanged). Unit 2.1
adds :func:`run_order_idor`, the **active** path: given two operator-supplied
identities it logs each in, then builds a finding whose deterministic replay reads
the owner's resource under both sessions and is VERIFIED only if the second
account receives the owner's exact object. Reading is not state-changing, so this
path is ungated (it needs two sessions, not an approval gate).
"""

from __future__ import annotations

from urllib.parse import urljoin

from finlexpurple.detectors.prober import Prober
from finlexpurple.detectors.schema import Finding, Severity
from finlexpurple.finance.idor_identities import IdorIdentities
from finlexpurple.finance.payment_tests._common import candidate_finding, param_set, path_of
from finlexpurple.recon.endpoint_catalog import Endpoint
from finlexpurple.verifier import engine as verifier_engine

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


def acquire_session(prober: Prober, login_url: str, user: str) -> dict[str, str] | None:
    """Log ``user`` in and return a ``Cookie`` header for their session, or None.

    Posts the username to the login endpoint (as a query value, which the lab's
    login reads) and extracts the session cookie's ``name=value`` from the
    response's ``Set-Cookie``. Returns None if login did not succeed or set a
    cookie — in which case verification cannot run and stays honest.
    """

    response = prober.request("POST", login_url, params={"user": user})
    if response.status_code != 200:
        return None
    set_cookie = response.headers.get("set-cookie")
    if not set_cookie:
        return None
    cookie = set_cookie.split(";", 1)[0].strip()  # "session=..." without attributes
    return {"Cookie": cookie} if cookie else None


def run_order_idor(
    origin: str,
    *,
    agent: str,
    prober: Prober | None,
    identities: IdorIdentities | None,
) -> list[Finding]:
    """Actively capture + verify order-IDOR using two authenticated sessions.

    Returns a single verified-or-not ``order_idor`` finding when both identities
    authenticate, or ``[]`` when there is no prober, no identities, or login
    fails (so a scan without configured identities produces no active finding —
    the passive candidate still covers the surface). The finding's status is set
    by the deterministic replay: VERIFIED only on a reproduced cross-account read.
    """

    if prober is None or identities is None or identities.owner.order_path is None:
        return []
    login_url = urljoin(origin, identities.login_path)
    owner_headers = acquire_session(prober, login_url, identities.owner.user)
    other_headers = acquire_session(prober, login_url, identities.other.user)
    if owner_headers is None or other_headers is None:
        return []
    url = urljoin(origin, identities.owner.order_path)
    finding = Finding.new(
        vulnerability_class="order_idor",
        method="GET",
        url=url,
        payload=f"order_idor:{identities.owner.order_path}",
        expected_signal=(
            "a second authenticated account reads the owner's exact order object via a "
            "per-user resource with no per-object authorization; reproduced only if both "
            "sessions return the identical object"
        ),
        severity=Severity.HIGH,
        agent=agent,
    )
    verifier_engine.verify(finding, prober=prober, sessions=(owner_headers, other_headers))
    return [finding]
