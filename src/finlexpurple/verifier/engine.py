"""The verification engine (Phase 11; decisions.md §6).

``verify`` is the single entry point: it dispatches a finding to the replay
adapter for its vulnerability class, runs the deterministic replay, and updates
the finding's ``status`` and ``verification_log`` from the result. A class with
no replay engine stays ``reported``. The only route to ``verified`` is a replay
that actually reproduced the exploit — never an LLM's confidence, which is never
consulted here.

Since Unit 1.6 the class → replay mapping is read from the one capability
registry (:mod:`finlexpurple.capabilities`) rather than a hand-maintained
``if/elif`` chain, so a new class is added by one registry record — with no edit
to this module. The replay modules themselves are unchanged, so
``verifier.status.status_for`` remains the only producer of ``verified``.
"""

from __future__ import annotations

from finlexpurple import capabilities
from finlexpurple.detectors.prober import Prober
from finlexpurple.detectors.schema import Finding
from finlexpurple.gates.approval_gate import ApprovalGate
from finlexpurple.verifier.replay.canary import OutOfBandCanary
from finlexpurple.verifier.replay.coupon_abuse_replay import CouponConfirmer
from finlexpurple.verifier.replay.price_tampering_replay import ChargeConfirmer
from finlexpurple.verifier.replay.webhook_bypass_replay import SettlementConfirmer
from finlexpurple.verifier.replay.xss_replay import BrowserRunner
from finlexpurple.verifier.status import ReplayResult, status_for

# Re-exported for back-compat (idor sessions are a (owner, other) header pair).
Sessions = capabilities.Sessions


def verify(
    finding: Finding,
    *,
    prober: Prober | None = None,
    sessions: Sessions | None = None,
    canary: OutOfBandCanary | None = None,
    browser_runner: BrowserRunner | None = None,
    gate: ApprovalGate | None = None,
    charge_confirmer: ChargeConfirmer | None = None,
    settlement_confirmer: SettlementConfirmer | None = None,
    coupon_confirmer: CouponConfirmer | None = None,
) -> Finding:
    """Replay ``finding`` by its class and update its status/verification_log in place.

    Collaborators are per class: SQLi needs a prober; IDOR a prober + two
    sessions; SSRF a prober + an out-of-band canary; XSS a headless-browser
    runner; price-tampering a prober + an approval ``gate`` (its re-execution is
    state-changing) + an optional ``charge_confirmer`` (durable-state read-back);
    webhook-bypass a prober + an approval ``gate`` + an optional
    ``settlement_confirmer`` (paid-state read-back). A missing collaborator or an
    unknown class leaves the finding ``reported``; without a ``gate`` a
    price-tampering or webhook-bypass finding can never become ``verified``. The
    collaborators are bundled into one :class:`capabilities.ReplayContext` and the
    class's replay adapter takes only what it needs.
    """

    context = capabilities.ReplayContext(
        prober=prober,
        sessions=sessions,
        canary=canary,
        browser_runner=browser_runner,
        gate=gate,
        charge_confirmer=charge_confirmer,
        settlement_confirmer=settlement_confirmer,
        coupon_confirmer=coupon_confirmer,
    )
    capability = capabilities.capability_for(finding.vulnerability_class)
    if capability is None or capability.replay is None:
        result = ReplayResult(None, f"no replay engine for class {finding.vulnerability_class!r}.")
    else:
        result = capability.replay(finding, context)

    finding.status = status_for(result)
    finding.verification_log = result.log
    return finding
