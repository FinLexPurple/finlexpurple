"""Structured execution boundary for planned detector calls.

This module is the "act" side of the orchestration loop and exists to satisfy
the architecture.md Phase 6 acceptance item that *detector execution must be
deterministic code, never free-form LLM output*: the executor only ever
dispatches a planned action to a registered detector callable using the
action's structured fields. It never parses model prose and never lets a
detector's return value widen beyond the known schema.

Two detectors implement the same ``run(endpoint_record) -> {"findings": [...]}``
contract:

* :class:`StubDetector` — the inert default (used by tests and any path that
  does not wire real detection); it never reports a finding.
* :class:`WebDetector` — the real path (Phase 10 detectors + Phase 11
  verification) that the ``scan`` command injects under the same action slot.

Crucially, the *persisted* observation stays findings-empty for **both**:
``RunState`` deliberately keeps request/response values out of ``run-state.json``
(a privacy guarantee), so the real findings are collected into an in-memory
``sink`` the caller owns and written only to the 0600 report tree — never into
the persisted run state.
"""

from __future__ import annotations

from collections.abc import MutableSequence
from typing import Any
from urllib.parse import urljoin

from finlexpurple.detectors import dispatch
from finlexpurple.detectors.prober import Prober
from finlexpurple.detectors.schema import Finding
from finlexpurple.gates.approval_gate import ApprovalGate
from finlexpurple.recon.endpoint_catalog import Endpoint
from finlexpurple.recon.fingerprint import Fingerprint
from finlexpurple.verifier import engine as verifier_engine
from finlexpurple.verifier.replay.canary import OutOfBandCanary
from finlexpurple.verifier.replay.coupon_abuse_replay import CouponConfirmer
from finlexpurple.verifier.replay.price_tampering_replay import ChargeConfirmer
from finlexpurple.verifier.replay.webhook_bypass_replay import SettlementConfirmer


class StubDetector:
    """Inert default detector that can never report a finding.

    It stands in wherever real detection is not wired (tests, dry runs).
    Returning a fixed empty-findings result keeps the loop honest: that path
    cannot appear to "find" anything.
    """

    def run(self, endpoint: dict[str, Any]) -> dict[str, Any]:
        """Return an empty-findings result, ignoring the endpoint entirely."""

        del endpoint
        return {"findings": []}


class WebDetector:
    """Real web detection + verification for one planned endpoint.

    Reconstructs a full :class:`Endpoint` from the persisted catalog record and
    the run's ``origin`` (the persisted record holds only the path, never query
    values), runs the Phase 10 detectors through a scope-safe prober, then runs
    each finding through the Phase 11 verification engine so it ends
    ``verified`` or ``reported``. It also runs the financial replay specialists —
    price-tampering and webhook-bypass: capture is an in-scope detection probe,
    and each verification *re-execution* is state-changing, so it routes through
    the injected approval ``gate`` and is confirmed only by an in-scope read-back
    (``charge_confirmer`` for a charged price, ``settlement_confirmer`` for a paid
    order) — without a gate they stay ``reported``, exactly as the other
    unverifiable classes do. Findings are appended to the caller's ``sink``; the returned
    observation is **always findings-empty** so the persisted run state keeps no
    request/response values (the same privacy guarantee the stub path upheld).
    """

    def __init__(
        self,
        *,
        origin: str,
        prober: Prober,
        sink: MutableSequence[Finding],
        fingerprint: Fingerprint | None = None,
        canary: OutOfBandCanary | None = None,
        gate: ApprovalGate | None = None,
        charge_confirmer: ChargeConfirmer | None = None,
        settlement_confirmer: SettlementConfirmer | None = None,
        coupon_confirmer: CouponConfirmer | None = None,
        run_financial: bool = True,
    ) -> None:
        self._origin = origin
        self._prober = prober
        self._sink = sink
        self._fingerprint = fingerprint
        self._canary = canary
        self._gate = gate
        self._charge_confirmer = charge_confirmer
        self._settlement_confirmer = settlement_confirmer
        self._coupon_confirmer = coupon_confirmer
        # The scan front-door selector (Decision 1) sets this: the financial
        # price-tampering step runs only when the selector chose the 'cashier'
        # specialist for this target, so a non-payment target never gets probed.
        self._run_financial = run_financial

    def run(self, endpoint: dict[str, Any]) -> dict[str, Any]:
        """Detect and verify findings for ``endpoint``; collect them in the sink."""

        reconstructed = Endpoint(
            method=str(endpoint["method"]),
            url=urljoin(self._origin, str(endpoint["path"])),
            parameters=tuple(endpoint.get("parameter_names", [])),
            content_type=endpoint.get("content_type"),
        )
        findings = dispatch.run_relevant(reconstructed, self._prober, self._fingerprint)
        for finding in findings:
            # Per-finding agent attribution (§16): web-detection findings are the
            # work of the 'hunter' detection agent. Set it only if a detector did
            # not already self-attribute, so a future specialist is not overwritten.
            if finding.agent is None:
                finding.agent = "hunter"
            # Deterministic replay sets the status; collaborators it lacks (e.g.
            # a second IDOR session, an XSS browser) leave that class reported.
            verifier_engine.verify(finding, prober=self._prober, canary=self._canary)
        self._sink.extend(findings)

        # Financial: the replay-backed classes (price-tampering, webhook-bypass).
        # Capture actively sends a state-changing probe (a tampered request / a
        # forged callback), so it is gated (Phase 8) BEFORE anything is sent; on a
        # denied/paused/absent gate nothing is sent and the lead stays a passive,
        # name-based [REPORTED] candidate. This is the SAME helper the isolated
        # cashier agent uses (agents.registry), so a scan and a `run --agent cashier`
        # reach identical statuses. Attributed to 'cashier' (standard gate); a
        # Teller/Vault category would be hard-gated. finance/ is imported lazily so
        # orchestrator keeps no finance import. Skipped entirely unless the selector
        # chose 'cashier' for this target (Decision 1).
        if self._run_financial:
            from finlexpurple.finance.payment_tests import financial_specialist

            self._sink.extend(financial_specialist.capture_and_verify(
                reconstructed, agent="cashier", prober=self._prober, gate=self._gate,
                charge_confirmer=self._charge_confirmer, settlement_confirmer=self._settlement_confirmer,
                coupon_confirmer=self._coupon_confirmer,
            ))

        # Persisted observation stays findings-empty (privacy guarantee); the
        # real findings live only in the sink / the 0600 report tree.
        return {"findings": []}


class Executor:
    """Dispatch typed actions to registered detector callables.

    The executor is the single point where a planned action turns into a
    detector call. Holding the detector registry here (rather than letting the
    planner or engine call detectors directly) keeps execution deterministic
    and auditable: everything that can run is named in ``self._detectors``. The
    default registry is the inert stub; the ``scan`` command injects a
    :class:`WebDetector` under the same ``phase8_stub`` slot for real detection.
    """

    def __init__(self, detectors: dict[str, Any] | None = None) -> None:
        """Register the available detectors (default: the inert stub)."""

        self._detectors = detectors if detectors is not None else {"phase8_stub": StubDetector()}

    def execute(self, action: dict[str, Any]) -> dict[str, Any]:
        """Run one planned action and return its structured observation.

        ``action`` is a planner-produced record of the shape
        ``{"action_id", "detector", "endpoint"}``. Returns
        ``{"action_id", "findings": [...]}`` (the persisted observation is
        findings-empty; real findings flow through a detector's sink). Raises
        ``TypeError`` if the ``detector`` field is not a string and
        ``ValueError`` if it names a detector that is not registered.
        """

        detector_name = action.get("detector")
        if not isinstance(detector_name, str):
            # A non-string detector name is a structural type error in the
            # action, so TypeError (not ValueError) is the correct signal.
            raise TypeError("Planned action references an unavailable detector.")
        detector = self._detectors.get(detector_name)
        if detector is None:
            raise ValueError("Planned action references an unavailable detector.")
        result = detector.run(action["endpoint"])
        return {"action_id": action["action_id"], **result}
