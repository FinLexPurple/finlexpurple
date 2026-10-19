"""Safe-failure framework (Phase 7; decisions.md §28 item 10).

The guarantee: if a run crashes or is killed, the target is never left in a
half-exploited state — the agent stops only at *safe points*. This module is
the reusable abstraction the later active modules (Phase 9 MCP, Phase 10
detectors, the Phase 19 financial agents) build their state-changing steps on;
the Phase 8 kill switch calls :meth:`request_stop`.

Two primitives:

* ``checkpoint()`` is a safe point. Call it between discrete steps. If a stop
  was requested, it raises :class:`StoppedAtSafePoint` here — a clean halt at a
  known-good boundary.
* ``critical_section(rollback=...)`` wraps a step that must not be interrupted
  half-way. Stop requests are **deferred** while inside it (so the step
  finishes), and if the step raises, the provided rollback runs before the
  error propagates, so no partial state is left behind.

Per decisions.md §18 item 14, exactly what constitutes a "safe point" for each
vulnerability class is still to be defined; this phase provides the mechanism,
not the per-class policy.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Iterator
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class StoppedAtSafePoint(RuntimeError):
    """Raised at a checkpoint when a stop was requested — a clean, safe halt."""


class SafeFailureController:
    """Coordinates cooperative stop requests and uninterruptible critical sections.

    A stop requested while inside one or more critical sections is held until the
    outermost section exits, at which point the next ``checkpoint`` honors it.
    """

    def __init__(self) -> None:
        self._stop_requested = False
        self._critical_depth = 0

    @property
    def stop_requested(self) -> bool:
        return self._stop_requested

    @property
    def in_critical_section(self) -> bool:
        return self._critical_depth > 0

    def request_stop(self) -> None:
        """Ask the run to halt at the next safe point (called by the kill switch)."""

        if not self._stop_requested:
            logger.warning("Stop requested; the run will halt at the next safe point.")
        self._stop_requested = True

    def checkpoint(self) -> None:
        """A safe point: halt cleanly here if a stop was requested and we are not mid-step."""

        if self._stop_requested and self._critical_depth == 0:
            raise StoppedAtSafePoint("Run halted at a safe point after a stop request.")

    @contextmanager
    def critical_section(self, rollback: Callable[[], None] | None = None) -> Iterator[None]:
        """Run an uninterruptible step; on failure, roll back so no partial state remains.

        Stop requests are deferred for the duration. If the body raises, the
        rollback (if given) runs before the exception propagates — the step is
        either fully done or fully undone, never half-applied.
        """

        self._critical_depth += 1
        try:
            yield
        except BaseException:
            if rollback is not None:
                try:
                    rollback()
                except Exception:
                    # A rollback failure must not mask the original error.
                    logger.exception("Rollback during a critical section failed.")
            raise
        finally:
            self._critical_depth -= 1
