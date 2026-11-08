"""The capability contract: one declarative record per vulnerability class (Unit 1.6).

This is the **single source of truth** that both detector dispatch
(:mod:`finlexpurple.detectors.dispatch`) and the verification engine
(:mod:`finlexpurple.verifier.engine`) read from, replacing the parallel maps
those modules used to hand-maintain. A class is described once, here, by a frozen
:class:`Capability`:

* ``vulnerability_class`` — the unique key (matches ``Finding.vulnerability_class``).
* ``detector`` — the candidate-finding producer run during a scan, with the
  uniform web signature ``(Endpoint, Prober) -> list[Finding]`` (``None`` for a
  class whose capture is orchestrated elsewhere, e.g. the gated financial
  specialist).
* ``relevance`` — for web dispatch: whether this detector is worth running
  against a given endpoint's shape (``None`` means "not shape-dispatched").
* ``replay`` — an adapter ``(Finding, ReplayContext) -> ReplayResult`` that pulls
  the collaborators it needs out of the context and calls the existing replay
  module unchanged (``None`` = no replay engine → the finding stays ``reported``).
* ``required_collaborators`` — the collaborators a replay needs to reach
  ``verified`` (declared, for introspection and validation).
* ``gate_category`` — ``None`` (ungated web replay) or ``DERIVE_FROM_AGENT`` (the
  financial classes, whose gate category is the acting agent).
* ``evidence_shape`` — a short, descriptive label for the evidence the class
  captures.
* ``agent`` / ``family`` — attribution.

**Adding a new class is one record plus its detector/replay — with zero edits to
the dispatch or engine core.** The invariants from Units 1.1–1.3 hold: the replay
adapters call the same replay modules, so ``verifier.status.status_for`` stays
the only route to ``verified``, hard-gated classes can never be auto-allowed, and
no LLM is consulted. This module imports detectors and replay modules only; it
never imports ``dispatch`` or ``engine``, so there is no import cycle.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field

from finlexpurple.detectors import (
    auth_misconfig,
    cache_poisoning,
    generic_misconfig,
    idor,
    sqli,
    ssrf,
    xss,
)
from finlexpurple.detectors.prober import Prober
from finlexpurple.detectors.schema import Finding
from finlexpurple.gates.approval_gate import ApprovalGate
from finlexpurple.recon.endpoint_catalog import Endpoint
from finlexpurple.verifier.replay import (
    cache_poisoning_replay,
    coupon_abuse_replay,
    idor_replay,
    order_idor_replay,
    payment_status_trust_replay,
    price_tampering_replay,
    race_condition_replay,
    refund_abuse_replay,
    sqli_replay,
    ssrf_replay,
    webhook_bypass_replay,
    xss_replay,
)
from finlexpurple.verifier.replay.canary import OutOfBandCanary
from finlexpurple.verifier.replay.coupon_abuse_replay import CouponConfirmer
from finlexpurple.verifier.replay.payment_status_trust_replay import PaymentStatusConfirmer
from finlexpurple.verifier.replay.price_tampering_replay import ChargeConfirmer
from finlexpurple.verifier.replay.race_condition_replay import RaceConfirmer
from finlexpurple.verifier.replay.refund_abuse_replay import RefundConfirmer
from finlexpurple.verifier.replay.webhook_bypass_replay import SettlementConfirmer
from finlexpurple.verifier.replay.xss_replay import BrowserRunner
from finlexpurple.verifier.status import ReplayResult

Sessions = tuple[dict[str, str], dict[str, str]]

# The collaborator vocabulary a replay may declare it needs (Unit 1.6).
PROBER = "prober"
SESSIONS = "sessions"
CANARY = "canary"
BROWSER_RUNNER = "browser_runner"
GATE = "gate"
CHARGE_CONFIRMER = "charge_confirmer"
SETTLEMENT_CONFIRMER = "settlement_confirmer"

# The gate_category policy for a class whose category is the acting agent (so a
# Teller/Vault agent is hard-gated, a Cashier is standard-gated).
DERIVE_FROM_AGENT = "derive_from_agent"


@dataclass(frozen=True)
class ReplayContext:
    """Every optional verification collaborator, bundled for a uniform replay call.

    The engine builds one of these from its keyword arguments and hands it to a
    capability's :attr:`Capability.replay` adapter; the adapter takes only what
    its class needs. Nothing here is required — a missing collaborator simply
    leaves the finding non-verified, exactly as before.
    """

    prober: Prober | None = None
    sessions: Sessions | None = None
    canary: OutOfBandCanary | None = None
    browser_runner: BrowserRunner | None = None
    gate: ApprovalGate | None = None
    charge_confirmer: ChargeConfirmer | None = None
    settlement_confirmer: SettlementConfirmer | None = None
    coupon_confirmer: CouponConfirmer | None = None
    payment_status_confirmer: PaymentStatusConfirmer | None = None
    refund_confirmer: RefundConfirmer | None = None
    race_confirmer: RaceConfirmer | None = None


WebDetector = Callable[[Endpoint, Prober], list[Finding]]
Relevance = Callable[[Endpoint], bool]
ReplayAdapter = Callable[[Finding, ReplayContext], ReplayResult]


@dataclass(frozen=True)
class Capability:
    """One declarative record describing a single vulnerability class."""

    vulnerability_class: str
    family: str
    detector: WebDetector | None = None
    relevance: Relevance | None = None
    replay: ReplayAdapter | None = None
    required_collaborators: frozenset[str] = field(default_factory=frozenset)
    gate_category: str | None = None
    evidence_shape: str = ""
    agent: str | None = None


# --- Relevance predicates (identical to the pre-1.6 dispatch shape logic) ------


def _has_params(endpoint: Endpoint) -> bool:
    return bool(endpoint.parameters)


def _has_id_param(endpoint: Endpoint) -> bool:
    return bool(endpoint.parameters) and any(
        idor.looks_like_id_param(param) for param in endpoint.parameters
    )


def _has_url_param(endpoint: Endpoint) -> bool:
    return bool(endpoint.parameters) and any(
        ssrf.accepts_url_param(param) for param in endpoint.parameters
    )


def _always(endpoint: Endpoint) -> bool:
    del endpoint
    return True


# --- Replay adapters (thin; call the existing replay modules unchanged) --------


def _sqli_replay(finding: Finding, ctx: ReplayContext) -> ReplayResult:
    return sqli_replay.replay(finding, ctx.prober)


def _idor_replay(finding: Finding, ctx: ReplayContext) -> ReplayResult:
    return idor_replay.replay(finding, ctx.prober, ctx.sessions)


def _ssrf_replay(finding: Finding, ctx: ReplayContext) -> ReplayResult:
    return ssrf_replay.replay(finding, ctx.prober, ctx.canary)


def _xss_replay(finding: Finding, ctx: ReplayContext) -> ReplayResult:
    return xss_replay.replay(finding, ctx.browser_runner)


def _cache_poisoning_replay(finding: Finding, ctx: ReplayContext) -> ReplayResult:
    del ctx  # cache-poisoning replay needs no collaborator
    return cache_poisoning_replay.replay(finding)


def _price_tampering_replay(finding: Finding, ctx: ReplayContext) -> ReplayResult:
    return price_tampering_replay.replay(finding, ctx.prober, ctx.gate, ctx.charge_confirmer)


def _webhook_bypass_replay(finding: Finding, ctx: ReplayContext) -> ReplayResult:
    return webhook_bypass_replay.replay(finding, ctx.prober, ctx.gate, ctx.settlement_confirmer)


def _order_idor_replay(finding: Finding, ctx: ReplayContext) -> ReplayResult:
    return order_idor_replay.replay(finding, ctx.prober, ctx.sessions)


def _coupon_abuse_replay(finding: Finding, ctx: ReplayContext) -> ReplayResult:
    return coupon_abuse_replay.replay(finding, ctx.prober, ctx.gate, ctx.coupon_confirmer)


def _payment_status_trust_replay(finding: Finding, ctx: ReplayContext) -> ReplayResult:
    return payment_status_trust_replay.replay(
        finding, ctx.prober, ctx.gate, ctx.payment_status_confirmer
    )


def _refund_abuse_replay(finding: Finding, ctx: ReplayContext) -> ReplayResult:
    return refund_abuse_replay.replay(finding, ctx.prober, ctx.gate, ctx.refund_confirmer)


def _race_condition_replay(finding: Finding, ctx: ReplayContext) -> ReplayResult:
    return race_condition_replay.replay(finding, ctx.prober, ctx.gate, ctx.race_confirmer)


# --- The registry -------------------------------------------------------------
#
# Order matters: web dispatch yields detectors in this order, so a scan's finding
# set stays byte-identical to the pre-1.6 dispatch (golden parity). The order
# mirrors the old dispatch.relevant_detectors append order exactly:
# sqli, xss, idor, ssrf, then the always-on response/header checks.

_CAPABILITIES: tuple[Capability, ...] = (
    Capability(
        vulnerability_class="sqli",
        family="web",
        detector=sqli.detect,
        relevance=_has_params,
        replay=_sqli_replay,
        required_collaborators=frozenset({PROBER}),
        evidence_shape="http_request_response",
        agent="hunter",
    ),
    Capability(
        vulnerability_class="xss",
        family="web",
        detector=xss.detect,
        relevance=_has_params,
        replay=_xss_replay,
        required_collaborators=frozenset({BROWSER_RUNNER}),
        evidence_shape="reflected_payload",
        agent="hunter",
    ),
    Capability(
        vulnerability_class="idor",
        family="web",
        detector=idor.detect,
        relevance=_has_id_param,
        replay=_idor_replay,
        required_collaborators=frozenset({PROBER, SESSIONS}),
        evidence_shape="cross_session_response",
        agent="hunter",
    ),
    Capability(
        vulnerability_class="ssrf",
        family="web",
        detector=ssrf.detect,
        relevance=_has_url_param,
        replay=_ssrf_replay,
        required_collaborators=frozenset({PROBER, CANARY}),
        evidence_shape="oob_interaction",
        agent="hunter",
    ),
    Capability(
        vulnerability_class="generic_misconfig",
        family="web",
        detector=generic_misconfig.detect,
        relevance=_always,
        replay=None,  # no replay engine → stays reported (unchanged behaviour)
        evidence_shape="header_response",
        agent="hunter",
    ),
    Capability(
        vulnerability_class="auth_misconfig",
        family="web",
        detector=auth_misconfig.detect,
        relevance=_always,
        replay=None,
        evidence_shape="header_response",
        agent="hunter",
    ),
    Capability(
        vulnerability_class="cache_poisoning",
        family="web",
        detector=cache_poisoning.detect,
        relevance=_always,
        replay=_cache_poisoning_replay,
        required_collaborators=frozenset(),
        evidence_shape="header_response",
        agent="hunter",
    ),
    # Financial replay-backed classes. Their candidate capture is state-changing
    # and is orchestrated (and gated) by finance.payment_tests.financial_specialist
    # and the scan executor, so there is no shape-dispatched ``detector`` here;
    # the capability supplies the replay + its contract. The gate category is the
    # acting agent (Cashier = standard; Teller/Vault = hard-gated).
    Capability(
        vulnerability_class="price_tampering",
        family="financial",
        detector=None,
        relevance=None,
        replay=_price_tampering_replay,
        required_collaborators=frozenset({PROBER, GATE}),
        gate_category=DERIVE_FROM_AGENT,
        evidence_shape="charged_amount_readback",
        agent=None,
    ),
    Capability(
        vulnerability_class="webhook_bypass",
        family="financial",
        detector=None,
        relevance=None,
        replay=_webhook_bypass_replay,
        required_collaborators=frozenset({PROBER, GATE}),
        gate_category=DERIVE_FROM_AGENT,
        evidence_shape="settlement_readback",
        agent=None,
    ),
    # Order IDOR (Unit 2.1): a two-session cross-account READ, so it is NOT gated
    # (reading is not state-changing) — hence no gate_category — and its collaborators
    # are a prober + two authenticated sessions (owner + other), not a gate/confirmer.
    Capability(
        vulnerability_class="order_idor",
        family="financial",
        detector=None,
        relevance=None,
        replay=_order_idor_replay,
        required_collaborators=frozenset({PROBER, SESSIONS}),
        gate_category=None,
        evidence_shape="cross_session_response",
        agent=None,
    ),
    # Coupon abuse (Unit 2.2): applying a coupon mutates the cart, so it is gated
    # (state-changing) and verified by an order-status read-back that shows the
    # bogus coupon's discount durably applied.
    Capability(
        vulnerability_class="coupon_abuse",
        family="financial",
        detector=None,
        relevance=None,
        replay=_coupon_abuse_replay,
        required_collaborators=frozenset({PROBER, GATE}),
        gate_category=DERIVE_FROM_AGENT,
        evidence_shape="discounted_total_readback",
        agent=None,
    ),
    # Payment-status trust (Unit 2.3): setting a client-controlled order status is
    # state-changing, so it is gated and verified by an order-status read-back
    # showing the order durably marked with the client-set status (no settlement).
    Capability(
        vulnerability_class="payment_status_trust",
        family="financial",
        detector=None,
        relevance=None,
        replay=_payment_status_trust_replay,
        required_collaborators=frozenset({PROBER, GATE}),
        gate_category=DERIVE_FROM_AGENT,
        evidence_shape="paid_status_readback",
        agent=None,
    ),
    # Refund abuse (Unit 2.4): issuing a refund exceeding the amount paid (no
    # amount/idempotency check) is state-changing, so it is gated and verified by a
    # refund-status read-back showing the order's refunded total durably exceeding
    # the amount paid. The gated re-send is itself the duplicate/double-refund case.
    Capability(
        vulnerability_class="refund_abuse",
        family="financial",
        detector=None,
        relevance=None,
        replay=_refund_abuse_replay,
        required_collaborators=frozenset({PROBER, GATE}),
        gate_category=DERIVE_FROM_AGENT,
        evidence_shape="over_refund_readback",
        agent=None,
    ),
    # Race condition (Unit 2.5): a check-then-act endpoint with no idempotency key or
    # lock. Verification is a BOUNDED, gated concurrency harness — never uncontrolled
    # concurrency — and it is reproduced only if an in-scope read-back shows the
    # operation durably double-processed THIS run. A genuine race is non-deterministic,
    # so the honest outcome is usually INCONCLUSIVE (a human-review lead), not VERIFIED.
    Capability(
        vulnerability_class="race_condition",
        family="financial",
        detector=None,
        relevance=None,
        replay=_race_condition_replay,
        required_collaborators=frozenset({PROBER, GATE}),
        gate_category=DERIVE_FROM_AGENT,
        evidence_shape="double_processing_readback",
        agent=None,
    ),
)

# Indexed by class for O(1) lookup; insertion order is preserved for dispatch.
_BY_CLASS: dict[str, Capability] = {cap.vulnerability_class: cap for cap in _CAPABILITIES}


def all_capabilities() -> tuple[Capability, ...]:
    """Every registered capability, in registry (dispatch) order."""

    return _CAPABILITIES


def capability_for(vulnerability_class: str) -> Capability | None:
    """Return the capability for ``vulnerability_class``, or ``None`` if unknown."""

    return _BY_CLASS.get(vulnerability_class)


def web_capabilities_for(endpoint: Endpoint) -> list[Capability]:
    """The web capabilities worth running against ``endpoint``, in dispatch order."""

    return [
        cap
        for cap in _CAPABILITIES
        if cap.family == "web"
        and cap.detector is not None
        and cap.relevance is not None
        and cap.relevance(endpoint)
    ]


def register(capability: Capability) -> None:
    """Register an additional capability at runtime (used by tests for a dummy class).

    A real class is normally added by appending a record to the registry above;
    this hook exists so a test can prove a brand-new capability dispatches and
    verifies with **zero** edits to the dispatch or engine core. Re-registering an
    existing class raises, so the unique-key invariant holds.
    """

    global _CAPABILITIES
    if capability.vulnerability_class in _BY_CLASS:
        raise ValueError(f"capability {capability.vulnerability_class!r} is already registered.")
    _CAPABILITIES = (*_CAPABILITIES, capability)
    _BY_CLASS[capability.vulnerability_class] = capability


def unregister(vulnerability_class: str) -> None:
    """Remove a previously :func:`register`-ed capability (test cleanup)."""

    global _CAPABILITIES
    _CAPABILITIES = tuple(c for c in _CAPABILITIES if c.vulnerability_class != vulnerability_class)
    _BY_CLASS.pop(vulnerability_class, None)
