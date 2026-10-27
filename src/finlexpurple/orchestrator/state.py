"""Serializable orchestration state and explicit stage transitions.

This is the hand-rolled state machine architecture.md Phase 6 calls for
(recon -> plan -> act -> observe -> verify -> report) and, with
``persistence.py``, underpins the acceptance item that *a killed run resumes
from run-state.json without repeating completed stages*. Two safety choices
drive the design: the state carries only non-sensitive metadata (endpoint
paths and parameter *names*, never query values, bodies, or responses), and
``from_dict`` revalidates every field on load so a tampered or malformed state
file is rejected rather than trusted. ``SCHEMA_VERSION`` gates forward
compatibility — later phases that enrich the state must bump it.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any, ClassVar


class InvalidRunStateError(ValueError):
    """A saved run state is malformed or uses an unsupported schema.

    Raised by ``RunState.from_dict`` (and surfaced by ``persistence.load_state``)
    so callers can distinguish an unusable/tampered state file from other errors.
    """


@dataclass
class RunState:
    """Minimal persisted run state; it contains no request or response values.

    Holds the current stage, the stages already completed, the recon-derived
    endpoint catalog and fingerprints, the pending/observed action records, and
    the bounded-run counters. By design it stores only metadata safe to write to
    disk: endpoint paths and parameter names, never query values or bodies.
    """

    # v2 adds ``spend_usd`` so the dollar spend cap (decisions.md §15) resumes
    # with the right amount already spent rather than resetting to zero.
    SCHEMA_VERSION: ClassVar[int] = 2
    STAGES: ClassVar[tuple[str, ...]] = (
        "recon", "plan", "act", "observe", "verify", "report"
    )

    run_id: str
    canonical_target: str
    current_stage: str = "recon"
    completed_stages: list[str] = field(default_factory=list)
    parameter_names: list[str] = field(default_factory=list)
    counters: dict[str, int | float] = field(
        default_factory=lambda: {"iterations": 0, "tool_calls": 0, "elapsed_seconds": 0}
    )
    catalog: list[dict[str, Any]] = field(default_factory=list)
    fingerprints: dict[str, Any] = field(
        default_factory=lambda: {"server": None, "technologies": []}
    )
    pending_actions: list[dict[str, Any]] = field(default_factory=list)
    observed_results: list[dict[str, Any]] = field(default_factory=list)
    disallow_paths: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    stop_reason: str | None = None
    # Cumulative USD spent on model calls this run; the dollar spend cap (§15)
    # halts the run resumably once it is reached. Kept out of ``counters`` because
    # that dict is validated to an exact, fixed key set.
    spend_usd: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable mapping stamped with the schema version."""

        return {"schema_version": self.SCHEMA_VERSION, **asdict(self)}

    @classmethod
    def from_dict(cls, raw: Any) -> RunState:
        """Rebuild and strictly validate a ``RunState`` from untrusted JSON.

        ``raw`` is whatever was parsed from a state file. Every field is checked
        for type and value (stages must be known, counters non-negative, catalog
        entries free of query values, pending actions limited to the Phase-6
        stub shape, and observed results empty) before a ``RunState`` is
        returned. Any deviation raises ``InvalidRunStateError``. This is
        intentionally strict: a resumed run is driven by this data, so a state
        file that has been corrupted or hand-edited must never be trusted.
        """

        # A missing/mismatched schema version is rejected first so an
        # incompatible file never reaches the per-field checks below.
        if not isinstance(raw, dict) or raw.get("schema_version") != cls.SCHEMA_VERSION:
            raise InvalidRunStateError("Run state is malformed or has an unsupported schema_version.")
        required = {
            "run_id", "canonical_target", "current_stage", "completed_stages",
            "parameter_names", "counters", "catalog", "fingerprints",
            "pending_actions", "observed_results", "disallow_paths", "warnings",
        }
        allowed = required | {"schema_version", "stop_reason", "spend_usd"}
        if not required.issubset(raw) or not set(raw).issubset(allowed):
            raise InvalidRunStateError("Run state is malformed or missing required fields.")
        try:
            state = cls(
                run_id=raw["run_id"], canonical_target=raw["canonical_target"],
                current_stage=raw["current_stage"], completed_stages=raw["completed_stages"],
                parameter_names=raw["parameter_names"], counters=raw["counters"],
                catalog=raw["catalog"], fingerprints=raw["fingerprints"],
                pending_actions=raw["pending_actions"],
                observed_results=raw["observed_results"],
                disallow_paths=raw["disallow_paths"], warnings=raw["warnings"],
                stop_reason=raw.get("stop_reason"),
                spend_usd=raw.get("spend_usd", 0.0),
            )
        except (KeyError, TypeError) as exc:
            raise InvalidRunStateError("Run state is malformed or missing required fields.") from exc
        if (
            not isinstance(state.run_id, str) or not state.run_id
            or not isinstance(state.canonical_target, str) or not state.canonical_target
            or state.current_stage not in cls.STAGES
            or not isinstance(state.completed_stages, list)
            or any(stage not in cls.STAGES for stage in state.completed_stages)
            or not isinstance(state.parameter_names, list)
            or any(not isinstance(name, str) for name in state.parameter_names)
            or not isinstance(state.counters, dict)
            or set(state.counters) != {"iterations", "tool_calls", "elapsed_seconds"}
            or any(type(value) not in (int, float) or value < 0 for value in state.counters.values())
            or not isinstance(state.catalog, list)
            or not isinstance(state.fingerprints, dict)
            or not isinstance(state.pending_actions, list)
            or not isinstance(state.observed_results, list)
            or not isinstance(state.disallow_paths, list)
            or not isinstance(state.warnings, list)
            or any(not isinstance(item, str) for item in state.warnings)
            or any(not isinstance(item, str) or "?" in item for item in state.disallow_paths)
            or not isinstance(state.stop_reason, (str, type(None)))
            or type(state.spend_usd) not in (int, float)
            or state.spend_usd < 0
        ):
            raise InvalidRunStateError("Run state is malformed or has invalid field values.")
        if not isinstance(state.fingerprints.get("server"), (str, type(None))) or not isinstance(
            state.fingerprints.get("technologies"), list
        ) or any(not isinstance(item, str) for item in state.fingerprints["technologies"]):
            raise InvalidRunStateError("Run state is malformed or has invalid field values.")
        for endpoint in state.catalog:
            if (
                not isinstance(endpoint, dict)
                or set(endpoint) != {"method", "path", "parameter_names", "content_type"}
                or not isinstance(endpoint["method"], str)
                or not isinstance(endpoint["path"], str)
                or not endpoint["path"].startswith("/")
                or "?" in endpoint["path"]
                or "#" in endpoint["path"]
                or not isinstance(endpoint["parameter_names"], list)
                or any(not isinstance(name, str) for name in endpoint["parameter_names"])
                or not isinstance(endpoint["content_type"], (str, type(None)))
            ):
                raise InvalidRunStateError("Run state is malformed or contains invalid catalog data.")
        for action in state.pending_actions:
            if (
                not isinstance(action, dict)
                or set(action) != {"action_id", "detector", "endpoint"}
                or action.get("detector") != "phase8_stub"
                or not isinstance(action.get("action_id"), str)
                or action.get("endpoint") not in state.catalog
            ):
                raise InvalidRunStateError("Run state is malformed or contains invalid planned actions.")
        if any(
            not isinstance(result, dict)
            or set(result) != {"action_id", "findings"}
            or not isinstance(result["action_id"], str)
            or result["findings"] != []
            for result in state.observed_results
        ):
            raise InvalidRunStateError("Run state is malformed or contains invalid detector results.")
        return state

    def advance(self, next_stage: str | None = None) -> None:
        """Complete the current stage and move to its single valid successor.

        ``next_stage`` may request a specific successor; otherwise the next
        stage in ``STAGES`` order is used. Only the transitions in ``allowed``
        are permitted — notably ``verify`` may loop back to ``plan`` (another
        round) or advance to ``report``, and ``report`` is terminal. An illegal
        transition raises ``InvalidRunStateError`` rather than silently moving.
        The current stage is appended to ``completed_stages`` before the move,
        which is what lets a resumed run skip finished stages.
        """

        index = self.STAGES.index(self.current_stage)
        default_next = self.STAGES[index + 1] if index + 1 < len(self.STAGES) else None
        chosen = next_stage or default_next
        # Explicit transition table: each stage lists its only legal successors.
        allowed = {
            "recon": {"plan"}, "plan": {"act"}, "act": {"observe"},
            "observe": {"verify"}, "verify": {"plan", "report"}, "report": set(),
        }
        if chosen not in allowed[self.current_stage]:
            raise InvalidRunStateError("The report stage is terminal.")
        self.completed_stages.append(self.current_stage)
        self.current_stage = chosen
