"""Order-IDOR replay — two-session cross-account read against the owner's view (Unit 2.1).

Re-reads a captured ``order_idor`` finding's owner-owned order resource under two
independent authenticated sessions — the resource **owner** (A) and a second,
non-owner account (B) — and decides, by deterministic code, whether B obtained
A's object without per-object authorization:

* ``REPRODUCED`` — B receives A's **exact** object (HTTP 200, non-empty, body
  identical to the owner's authorized view). Real cross-account access. -> VERIFIED
* ``NOT_REPRODUCED`` — B is denied (401/403/404 or empty), or B receives a
  *different* object than the owner's view (per-object authorization held, or B
  only ever sees its own resource). Not "the endpoint is secure" — only that this
  replay did not reproduce cross-account access.
* ``INCONCLUSIVE`` — the owner session could not read its own object (no 200 /
  empty), so there is no ground-truth view to compare B against.
* ``NO_ENGINE`` — the replay could not run (no prober, or no two sessions). -> REPORTED

Reading a resource is **not** state-changing, so — like the web ``idor`` replay,
and unlike price-tampering / webhook-bypass — this replay takes no approval gate.
The owner's own authorized read is the in-scope read-back that establishes ground
truth: B's response must equal A's exact object, so a coincidental 200 (an error
page, B's own order, a login redirect body) can never be mistaken for a leak. The
LLM is never consulted.
"""

from __future__ import annotations

from finlexpurple.detectors.prober import Prober
from finlexpurple.detectors.schema import Finding
from finlexpurple.verifier.status import ReplayOutcome, ReplayResult

Sessions = tuple[dict[str, str], dict[str, str]]

# Statuses that unambiguously mean the second account was refused the object.
_DENIED = frozenset({401, 403, 404})


def replay(finding: Finding, prober: Prober | None, sessions: Sessions | None) -> ReplayResult:
    """Reproduced iff a second account receives the owner's exact order object."""

    if prober is None or sessions is None:
        return ReplayResult(
            None,
            "order-IDOR replay requires a prober and two sessions (owner + other); not provided.",
            outcome=ReplayOutcome.NO_ENGINE,
        )
    owner_headers, other_headers = sessions

    # Ground truth: the owner's own authorized view of the captured resource.
    owner = prober.request(finding.method, finding.url, headers=owner_headers or None)
    if owner.status_code != 200 or not owner.text.strip():
        return ReplayResult(
            None,
            "the owner session could not read its own order object "
            f"(HTTP {owner.status_code}); no ground-truth view to compare against — inconclusive.",
            outcome=ReplayOutcome.INCONCLUSIVE,
        )

    # The cross-account attempt: a second account reads the same resource.
    other = prober.request(finding.method, finding.url, headers=other_headers or None)
    if other.status_code == 200 and other.text.strip() and other.text == owner.text:
        return ReplayResult(
            True,
            "a second account received the owner's exact order object "
            "(cross-account read reproduced against the owner's authorized view).",
            outcome=ReplayOutcome.REPRODUCED,
        )
    if other.status_code in _DENIED or not other.text.strip():
        return ReplayResult(
            False,
            f"the second account was denied the owner's object (HTTP {other.status_code}) "
            "— per-object authorization held; not reproduced.",
            outcome=ReplayOutcome.NOT_REPRODUCED,
        )
    return ReplayResult(
        False,
        "the second account received a different object than the owner's authorized view "
        "(not the owner's object) — not reproduced.",
        outcome=ReplayOutcome.NOT_REPRODUCED,
    )
