"""Kill switch / emergency stop (Phase 8; decisions.md §28 item 8).

Lets an operator halt an in-progress autonomous run **gracefully** — the run
stops at the next safe point with its state saved, never mid-step, so the target
is never left half-exploited. This is distinct from normal pause/resume: it is
an immediate operator-initiated stop.

Mechanically the kill switch only *requests* a stop (via Phase 7's
:class:`SafeFailureController`); the run's own checkpoints honor the request at a
safe boundary and the loop persists its state there. It never aborts a critical
section in flight.

Cross-platform signal handling:
* ``SIGINT`` (Ctrl+C) is handled on every OS.
* ``SIGTERM`` is handled on POSIX (macOS/Linux) only — Windows does not deliver
  it usefully, so it is skipped there.
* ``signal.signal`` only works on the main thread; if armed off the main thread
  (``ValueError``), the kill switch degrades to programmatic ``trigger()`` and
  logs it rather than crashing.
"""

from __future__ import annotations

import logging
import signal
import sys
from collections.abc import Callable
from types import FrameType
from typing import Any

from finlexpurple.security.safe_failure import SafeFailureController

logger = logging.getLogger(__name__)


def _signals() -> list[signal.Signals]:
    """Signals to trap: SIGINT everywhere, SIGTERM on POSIX only."""

    trapped: list[signal.Signals] = [signal.SIGINT]
    if sys.platform != "win32" and hasattr(signal, "SIGTERM"):
        trapped.append(signal.SIGTERM)
    return trapped


class KillSwitch:
    """Traps stop signals and requests a graceful halt at the next safe point."""

    def __init__(
        self,
        controller: SafeFailureController,
        *,
        on_stop: Callable[[], None] | None = None,
    ) -> None:
        self._controller = controller
        self._on_stop = on_stop
        # Values are whatever signal.getsignal returns (handler, SIG_DFL/SIG_IGN, or None).
        self._previous: dict[int, Any] = {}
        self._armed = False

    def trigger(self) -> None:
        """Request a graceful stop (callable directly or from a signal handler)."""

        logger.warning("Kill switch engaged: requesting a graceful stop at the next safe point.")
        self._controller.request_stop()
        if self._on_stop is not None:
            self._on_stop()

    def _handler(self, signum: int, frame: FrameType | None) -> None:
        del frame
        logger.warning("Received stop signal %s.", signal.Signals(signum).name)
        self.trigger()

    def arm(self) -> KillSwitch:
        """Install stop-signal handlers (main thread only); idempotent."""

        if self._armed:
            return self
        try:
            for sig in _signals():
                self._previous[sig] = signal.getsignal(sig)
                signal.signal(sig, self._handler)
            self._armed = True
        except ValueError:
            # Not on the main thread: signal handlers are unavailable here. The
            # programmatic trigger() still works.
            logger.warning("Kill switch could not install signal handlers (not on the main thread).")
            self._restore()
        return self

    def disarm(self) -> None:
        """Restore the previous signal handlers."""

        self._restore()
        self._armed = False

    def _restore(self) -> None:
        for sig, previous in self._previous.items():
            try:
                signal.signal(sig, previous)
            except (ValueError, OSError, TypeError):
                pass
        self._previous.clear()

    def __enter__(self) -> KillSwitch:  # noqa: PYI034 - `Self` is 3.11+, project targets 3.10
        return self.arm()

    def __exit__(self, *exc: object) -> None:
        self.disarm()
