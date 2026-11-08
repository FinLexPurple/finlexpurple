"""The activity stream renders pipeline steps with the right status glyphs and freezes on exit."""

from __future__ import annotations

import io

from finlexpurple.tui.activity import ActivityStream, Step, render_steps
from finlexpurple.tui.theme import make_console


def _render(steps: list[Step]) -> str:
    console = make_console(file=io.StringIO(), no_color=True, width=72)
    console.print(render_steps(steps))
    return console.file.getvalue()


def test_each_status_renders_its_glyph_and_label() -> None:
    out = _render([
        Step("recon", "done", "15 endpoints", started_at="12:00:00"),
        Step("replay", "running", started_at="12:00:01"),
        Step("gate", "blocked", "denied", started_at="12:00:02"),
        Step("verdict", "verified", started_at="12:00:03"),
    ])
    assert "✓ recon" in out and "15 endpoints" in out   # done
    assert "• replay" in out                            # running
    assert "⊘ gate" in out and "denied" in out          # blocked
    assert "✓ verdict" in out                           # verified
    assert "12:00:00" in out                                 # timestamp


def test_stream_records_steps_and_transitions() -> None:
    # Drive the stream with a non-terminal console (no_color StringIO); assert state, not pixels.
    console = make_console(file=io.StringIO(), no_color=True, width=72)
    with ActivityStream(console) as stream:
        i = stream.start("detect: refund_abuse")
        assert stream.steps[i].status == "running"
        stream.finish(i, status="done", detail="candidate")
        j = stream.start("gate: cashier approval")
        stream.block(j, reason="not approved")
    assert [s.status for s in stream.steps] == ["done", "blocked"]
    assert stream.steps[0].detail == "candidate" and stream.steps[1].detail == "not approved"
    # The final frame is left in the scrollback (transient=False).
    assert "refund_abuse" in console.file.getvalue()


def test_unknown_status_falls_back_to_waiting_glyph() -> None:
    out = _render([Step("x", "mystery", started_at="12:00:00")])
    assert "· x" in out  # waiting glyph, no crash
