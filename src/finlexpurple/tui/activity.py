"""The live activity stream for a chat turn (chat-only; imports rich).

As the agent works, each step — recon, detect, replay, gate, verdict — appears as a
timestamped line with a colored status word, updating in place during the turn and
**freezing into the scrollback** when the turn ends (a transient-while-active region, not a
persistent full-screen panel). Status colors come from the brand theme: running=gold,
done=teal, verified=green, blocked=gold, waiting=muted.

The rendering is separated from the live driving so it can be unit-tested by rendering a
fixed set of steps to a string.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from types import TracebackType

from rich.console import Console, Group
from rich.live import Live
from rich.text import Text

# Status -> (symbol, theme style). The vocabulary maps to our real pipeline outcomes.
_STATUS_STYLE: dict[str, tuple[str, str]] = {
    "waiting": ("·", "flp.waiting"),   # ·  queued / not started
    "running": ("•", "flp.running"),   # •  in progress
    "done": ("✓", "flp.done"),         # ✓  completed
    "verified": ("✓", "flp.verified"), # ✓  verified by replay
    "blocked": ("⊘", "flp.blocked"),   # ⊘  gate blocked / denied
    "failed": ("✗", "flp.muted"),      # ✗  errored
}


@dataclass
class Step:
    """One pipeline step in the activity stream."""

    label: str
    status: str = "running"
    detail: str = ""
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).strftime("%H:%M:%S"))


def render_steps(steps: list[Step]) -> Group:
    """Render the steps as a group of timestamped, status-colored lines."""

    lines: list[Text] = []
    for step in steps:
        symbol, style = _STATUS_STYLE.get(step.status, _STATUS_STYLE["waiting"])
        line = Text()
        line.append(f"{step.started_at} ", style="flp.muted")
        line.append(f"{symbol} ", style=style)
        line.append(step.label, style="flp.text")
        if step.detail:
            line.append(f"  {step.detail}", style="flp.muted")
        lines.append(line)
    return Group(*lines)


class ActivityStream:
    """A live, scrollback-freezing activity stream for one chat turn.

    Use as a context manager around a turn's work. ``start`` adds a running step and
    returns its index; ``update`` / ``finish`` / ``block`` move it to a terminal status.
    The region updates in place while active and the final frame remains in the scrollback
    on exit (``transient=False``), so the completed cards are part of the conversation.
    """

    def __init__(self, console: Console, *, refresh_per_second: float = 12.0) -> None:
        self._console = console
        self._steps: list[Step] = []
        self._live = Live(
            render_steps(self._steps),
            console=console,
            refresh_per_second=refresh_per_second,
            transient=False,
        )

    def __enter__(self) -> ActivityStream:  # noqa: PYI034 - `Self` is 3.11+, project targets 3.10
        self._live.start()
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self._refresh()
        self._live.stop()

    def _refresh(self) -> None:
        self._live.update(render_steps(self._steps))

    def start(self, label: str, *, detail: str = "") -> int:
        """Add a running step; returns its index for later updates."""

        self._steps.append(Step(label=label, status="running", detail=detail))
        self._refresh()
        return len(self._steps) - 1

    def update(self, index: int, *, status: str | None = None, detail: str | None = None) -> None:
        step = self._steps[index]
        if status is not None:
            step.status = status
        if detail is not None:
            step.detail = detail
        self._refresh()

    def finish(self, index: int, *, status: str = "done", detail: str = "") -> None:
        self.update(index, status=status, detail=detail)

    def block(self, index: int, *, reason: str = "") -> None:
        self.update(index, status="blocked", detail=reason)

    @property
    def steps(self) -> list[Step]:
        return self._steps
