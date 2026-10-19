"""Structured execution boundary for planned detector calls.

This module is the "act" side of the Phase 6 loop and exists to satisfy the
architecture.md Phase 6 acceptance item that *detector execution must be
deterministic code, never free-form LLM output*: the executor only ever
dispatches a planned action to a registered detector callable using the
action's structured fields. It never parses model prose and never lets a
detector's return value widen beyond the known schema. In Phase 6 the only
registered detector is an inert stub; Phase 8 replaces it with the real
detector registry without changing this dispatch contract.
"""

from __future__ import annotations

from typing import Any


class StubDetector:
    """Phase 6 placeholder detector that can never report a finding.

    It stands in for the real Phase 8 detectors so the orchestration loop can
    be exercised end to end before any detection logic exists. Returning a
    fixed empty-findings result keeps the loop honest: a run cannot appear to
    "find" anything until Phase 8 provides genuine detectors.
    """

    def run(self, endpoint: dict[str, Any]) -> dict[str, Any]:
        """Return an empty-findings result, ignoring the endpoint entirely.

        ``endpoint`` is the structured catalog record for the action; it is
        accepted for interface parity with real detectors but deliberately
        discarded here so the stub has no behavior to exploit.
        """

        del endpoint
        return {"findings": []}


class Executor:
    """Dispatch typed actions to registered detector callables.

    The executor is the single point where a planned action turns into a
    detector call. Holding the detector registry here (rather than letting the
    planner or engine call detectors directly) keeps execution deterministic
    and auditable: everything that can run is named in ``self._detectors``.
    """

    def __init__(self) -> None:
        """Register the detectors available this phase (only the Phase 8 stub)."""

        self._detectors = {"phase8_stub": StubDetector()}

    def execute(self, action: dict[str, Any]) -> dict[str, Any]:
        """Run one planned action and return its structured observation.

        ``action`` is a planner-produced record of the shape
        ``{"action_id", "detector", "endpoint"}``. Returns
        ``{"action_id", "findings": [...]}``. Raises ``TypeError`` if the
        ``detector`` field is not a string (a malformed action rather than a
        runtime fault) and ``ValueError`` if it names a detector that is not
        registered. Both guards are defensive: ``RunState`` validation already
        guarantees every persisted action names the ``phase8_stub`` detector.
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
        # Hard stop: even if a (future or tampered) detector tried to return
        # findings under the stub name, they are discarded here so Phase 6 can
        # never surface a finding before Phase 8/10 verification logic exists.
        if detector_name == "phase8_stub":
            result = {"findings": []}
        return {"action_id": action["action_id"], **result}
