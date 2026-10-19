"""Persisted plan/act/observe/verify control loop.

This is the engine that ties the Phase 6 pieces together and is where all three
architecture.md Phase 6 acceptance items converge: it saves state after every
stage transition so a run resumes without repeating completed stages
(``persistence.py``), it checks ``IterationLimits`` on every pass so a run that
would loop forever stops cleanly with a recorded reason, and it drives the
``Planner``/``Executor`` so that the model only reorders a fixed, deterministic
set of actions. The loop is intentionally the only place that mutates and
persists ``RunState``; every other module is a pure helper it calls.
"""

from __future__ import annotations

import hashlib
import logging
import time
from pathlib import Path
from typing import Any

from finlexpurple.orchestrator.executor import Executor
from finlexpurple.orchestrator.iteration_limits import IterationLimits
from finlexpurple.orchestrator.persistence import create_run_directory, save_state
from finlexpurple.orchestrator.planner import Planner
from finlexpurple.orchestrator.state import RunState
from finlexpurple.recon.crawler import ReconResult

logger = logging.getLogger(__name__)


def _safe_endpoint_records(recon: ReconResult) -> tuple[list[dict[str, Any]], list[str]]:
    """Reduce recon output to disk-safe catalog records plus a parameter-name set.

    Returns ``(catalog, sorted_parameter_names)`` where each catalog record keeps
    only method, URL path, parameter *names*, and content type. This is the
    boundary that keeps query values and bodies out of persisted state, matching
    the privacy guarantee ``RunState`` relies on.
    """

    catalog: list[dict[str, Any]] = []
    parameter_names: set[str] = set()
    for endpoint in recon.catalog.endpoints:
        # EndpointCatalog guarantees no query values; persist only path and names.
        from urllib.parse import urlsplit

        path = urlsplit(endpoint.url).path or "/"
        parameters = list(endpoint.parameters)
        parameter_names.update(parameters)
        catalog.append({
            "method": endpoint.method,
            "path": path,
            "parameter_names": parameters,
            "content_type": endpoint.content_type,
        })
    return catalog, sorted(parameter_names)


def state_from_recon(
    canonical_target: str,
    recon: ReconResult,
    *,
    reports_dir: Path | None = None,
) -> tuple[RunState, Path]:
    """Create initial persisted state after the Phase 5 recon stage."""

    run_id, directory = create_run_directory(canonical_target, reports_dir=reports_dir)
    catalog, parameter_names = _safe_endpoint_records(recon)
    state = RunState(
        run_id=run_id,
        canonical_target=canonical_target,
        current_stage="recon",
        catalog=catalog,
        parameter_names=parameter_names,
        fingerprints={
            "server": recon.fingerprint.server,
            "technologies": list(recon.fingerprint.technologies),
        },
        disallow_paths=list(recon.disallow_paths),
        warnings=list(recon.warnings),
        counters={"iterations": 0, "tool_calls": 0, "elapsed_seconds": 0},
    )
    return state, directory / "run-state.json"


def run(
    state: RunState,
    state_path: Path,
    *,
    planner: Planner | None = None,
    executor: Executor | None = None,
    limits: IterationLimits | None = None,
) -> RunState:
    """Run or resume state transitions, saving after each completed stage.

    Drives ``state`` from its current stage toward ``report``, persisting to
    ``state_path`` after every transition and after every detector call, so the
    run is resumable at any interruption point. ``planner``/``executor``/
    ``limits`` are injectable (defaults are constructed here) to keep the loop
    testable. If a limit is hit, the loop records ``state.stop_reason``,
    persists, and returns early; a run already at ``report`` is returned
    untouched. Returns the (mutated) ``state``.
    """

    active_planner = planner or Planner()
    active_executor = executor or Executor()
    active_limits = limits or IterationLimits.from_environment()
    # Already finished: nothing to do, and 'report' is terminal.
    if state.current_stage == "report":
        return state
    started = time.monotonic()
    # Time already spent in previous (resumed) segments, so wall-clock accounting
    # spans the whole run rather than just this invocation.
    elapsed_before = float(state.counters["elapsed_seconds"])

    def elapsed() -> float:
        """Total run seconds = time banked from prior segments + this segment."""

        return elapsed_before + time.monotonic() - started

    def reached(*, check_iterations: bool = True) -> str | None:
        """Return a stop reason if any iteration/tool-call/wall-clock cap is hit."""

        reason = active_limits.reached(
            state,
            started - elapsed_before,
            check_iterations=check_iterations,
        )
        if elapsed() >= active_limits.max_wall_clock_seconds:
            reason = f"wall-clock limit reached ({active_limits.max_wall_clock_seconds} seconds)"
            logger.warning("Orchestration stopped: %s", reason)
        return reason

    def save_current() -> None:
        """Bank elapsed time into the counters and atomically persist the state."""

        state.counters["elapsed_seconds"] = elapsed()
        save_state(state_path, state)

    def persist_transition(next_stage: str) -> None:
        """Advance to ``next_stage`` and persist, so the move survives a crash."""

        state.advance(next_stage)
        save_current()

    # Each iteration handles exactly one stage, persisting before looping, so a
    # kill at any point leaves a resumable state on disk.
    while state.current_stage != "report":
        reason = reached(check_iterations=state.current_stage == "plan")
        if reason:
            state.stop_reason = reason
            save_current()
            return state
        if state.current_stage == "recon":
            persist_transition("plan")
        elif state.current_stage == "plan":
            # Re-check the iteration cap here too: planning is the unit that can
            # loop (verify -> plan -> act -> ...), so a runaway is stopped before
            # another plan is produced.
            if state.counters["iterations"] >= active_limits.max_iterations:
                state.stop_reason = f"iteration limit reached ({active_limits.max_iterations})"
                logger.warning("Orchestration stopped: %s", state.stop_reason)
                save_current()
                return state
            completed = {item["action_id"] for item in state.observed_results}
            state.pending_actions = active_planner.plan(state.catalog, completed)
            state.counters["iterations"] += 1
            persist_transition("act")
        elif state.current_stage == "act":
            # Execute each planned action, persisting after every one so a kill
            # mid-stage resumes without repeating completed detector calls.
            while state.pending_actions:
                reason = reached(check_iterations=False)
                if reason:
                    state.stop_reason = reason
                    save_current()
                    return state
                action = state.pending_actions.pop(0)
                state.counters["tool_calls"] += 1
                result = active_executor.execute(action)
                state.observed_results.append(result)
                save_current()
            persist_transition("observe")
        elif state.current_stage == "observe":
            persist_transition("verify")
        elif state.current_stage == "verify":
            # Decide whether another round is warranted: if actions remain, or the
            # planner still finds unobserved work, loop back to plan; otherwise the
            # run is finished and advances to the terminal report stage.
            if state.pending_actions:
                persist_transition("plan")
            else:
                pending = active_planner.plan(
                    state.catalog,
                    {item["action_id"] for item in state.observed_results},
                )
                if pending:
                    persist_transition("plan")
                else:
                    persist_transition("report")
    state.stop_reason = None
    save_current()
    return state


def run_id_for_resume(state: RunState) -> str:
    """Validate a saved run identifier before its directory is trusted for resume.

    Recomputes the 8-char target hash and confirms it is present in the stored
    ``run_id``, and rejects any id containing path separators or ``..``. This
    binds the run directory to the canonical target and blocks a crafted state
    file from steering resume at a path outside the reports tree. Returns the
    validated ``run_id`` or raises ``ValueError``.
    """

    expected = hashlib.sha256(state.canonical_target.encode("utf-8")).hexdigest()[:8]
    if expected not in state.run_id or "/" in state.run_id or "\\" in state.run_id or ".." in state.run_id:
        raise ValueError("Cannot resume: run_id does not match the canonical target.")
    return state.run_id
