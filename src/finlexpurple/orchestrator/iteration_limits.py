"""Configurable hard caps for orchestration runs.

This module satisfies the architecture.md Phase 6 acceptance item that the
loop *must stop a run that would otherwise iterate indefinitely*. It defines
three independent ceilings — planning iterations, detector/tool calls, and
wall-clock seconds — with conservative defaults that the engine checks on
every pass. The caps are also the seed of Phase 18's budget guard; the dollar
spend cap is explicitly out of scope here and arrives with that phase.
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from time import monotonic

from finlexpurple.orchestrator.state import RunState

logger = logging.getLogger(__name__)


class IterationLimitConfigurationError(ValueError):
    """An orchestration limit environment variable is invalid."""


@dataclass(frozen=True)
class IterationLimits:
    """Immutable per-run ceilings for planning, tool calls, and wall-clock time.

    Frozen so a run's limits cannot be mutated mid-flight. Defaults are
    intentionally conservative (20 planning iterations, 50 detector/tool
    calls, 30 minutes) so an unattended run self-terminates long before it
    could loop or burn resources without bound.
    """

    max_iterations: int = 20
    max_tool_calls: int = 50
    max_wall_clock_seconds: int = 30 * 60

    def __post_init__(self) -> None:
        """Reject non-positive ceilings; a zero/negative cap would disable itself."""

        if min(self.max_iterations, self.max_tool_calls, self.max_wall_clock_seconds) < 1:
            raise ValueError("All orchestration limits must be positive integers.")

    @classmethod
    def from_environment(cls) -> IterationLimits:
        """Read optional positive-integer overrides from the process environment."""

        names = {
            "FINLEXPURPLE_MAX_ITERATIONS": "max_iterations",
            "FINLEXPURPLE_MAX_TOOL_CALLS": "max_tool_calls",
            "FINLEXPURPLE_MAX_RUN_SECONDS": "max_wall_clock_seconds",
        }
        values: dict[str, int] = {}
        for env_name, field_name in names.items():
            raw = os.environ.get(env_name)
            if raw is None:
                continue
            try:
                parsed = int(raw)
            except ValueError:
                raise IterationLimitConfigurationError(
                    f"{env_name} must be a positive integer."
                ) from None
            if parsed < 1:
                raise IterationLimitConfigurationError(
                    f"{env_name} must be a positive integer."
                )
            values[field_name] = parsed
        return cls(**values)

    def reached(
        self, state: RunState, started_at: float, *, check_iterations: bool = True
    ) -> str | None:
        """Return a human-readable stop reason if any cap is hit, else ``None``.

        ``state`` carries the live counters; ``started_at`` is the monotonic
        timestamp the current run segment began (already adjusted for time
        elapsed in prior, resumed segments). ``check_iterations`` is False
        while inside the ``act`` stage so a single plan's many tool calls are
        bounded by the tool-call cap rather than miscounted as iterations.
        A non-None return is logged here as well as acted on by the engine.
        """

        counters = state.counters
        reason = None
        if check_iterations and counters["iterations"] >= self.max_iterations:
            reason = f"iteration limit reached ({self.max_iterations})"
        elif counters["tool_calls"] >= self.max_tool_calls:
            reason = f"tool-call limit reached ({self.max_tool_calls})"
        elif monotonic() - started_at >= self.max_wall_clock_seconds:
            reason = f"wall-clock limit reached ({self.max_wall_clock_seconds} seconds)"
        if reason:
            logger.warning("Orchestration stopped: %s", reason)
        return reason
