"""The verification engine (Phase 11; decisions.md §6).

``verify`` is the single entry point: it dispatches a finding to the replay
module for its vulnerability class, runs the deterministic replay, and updates
the finding's ``status`` and ``verification_log`` from the result. A class with
no replay engine stays ``reported``. The only route to ``verified`` is a replay
that actually reproduced the exploit — never an LLM's confidence, which is never
consulted here.
"""

from __future__ import annotations

from finlexpurple.detectors.prober import Prober
from finlexpurple.detectors.schema import Finding
from finlexpurple.gates.approval_gate import ApprovalGate
from finlexpurple.verifier.replay import (
    cache_poisoning_replay,
    idor_replay,
    price_tampering_replay,
    sqli_replay,
    ssrf_replay,
    xss_replay,
)
from finlexpurple.verifier.replay.canary import OutOfBandCanary
from finlexpurple.verifier.replay.price_tampering_replay import ChargeConfirmer
from finlexpurple.verifier.replay.xss_replay import BrowserRunner
from finlexpurple.verifier.status import ReplayResult, status_for

Sessions = tuple[dict[str, str], dict[str, str]]


def verify(
    finding: Finding,
    *,
    prober: Prober | None = None,
    sessions: Sessions | None = None,
    canary: OutOfBandCanary | None = None,
    browser_runner: BrowserRunner | None = None,
    gate: ApprovalGate | None = None,
    charge_confirmer: ChargeConfirmer | None = None,
) -> Finding:
    """Replay ``finding`` by its class and update its status/verification_log in place.

    Collaborators are per class: SQLi needs a prober; IDOR a prober + two
    sessions; SSRF a prober + an out-of-band canary; XSS a headless-browser
    runner; price-tampering a prober + an approval ``gate`` (its re-execution is
    state-changing) + an optional ``charge_confirmer`` (durable-state read-back).
    A missing collaborator or an unknown class leaves the finding ``reported``;
    without a ``gate`` a price-tampering finding can never become ``verified``.
    """

    vulnerability_class = finding.vulnerability_class
    if vulnerability_class == "sqli":
        result = sqli_replay.replay(finding, prober)
    elif vulnerability_class == "idor":
        result = idor_replay.replay(finding, prober, sessions)
    elif vulnerability_class == "ssrf":
        result = ssrf_replay.replay(finding, prober, canary)
    elif vulnerability_class == "xss":
        result = xss_replay.replay(finding, browser_runner)
    elif vulnerability_class == "cache_poisoning":
        result = cache_poisoning_replay.replay(finding)
    elif vulnerability_class == "price_tampering":
        result = price_tampering_replay.replay(finding, prober, gate, charge_confirmer)
    else:
        result = ReplayResult(None, f"no replay engine for class {vulnerability_class!r}.")

    finding.status = status_for(result)
    finding.verification_log = result.log
    return finding
