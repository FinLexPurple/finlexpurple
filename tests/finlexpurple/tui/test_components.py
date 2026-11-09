"""The redesigned chat session screen renders the expected structure in the brand palette."""

from __future__ import annotations

import io

from finlexpurple.tui import components as C
from finlexpurple.tui.theme import make_console


def _render(renderable, *, color: bool, width: int = 100) -> str:
    console = make_console(file=io.StringIO(), no_color=not color, force_terminal=True, width=width)
    console.print(renderable)
    return console.file.getvalue()


def _render_truecolor(renderable, monkeypatch, *, width: int = 100) -> str:
    # Force 24-bit output so the exact brand hex appears (rich else downsamples to 256).
    monkeypatch.setenv("COLORTERM", "truecolor")
    monkeypatch.delenv("NO_COLOR", raising=False)
    return _render(renderable, color=True, width=width)


def test_wordmark_is_one_line_outlined_blocks() -> None:
    out = _render(C.wordmark(), color=False, width=120)
    lines = [ln for ln in out.splitlines() if ln.strip()]
    # Thin outlined block font: uses outline strokes, not solid █ fill.
    assert "|" in out and "_" in out and "█" not in out
    # One-line composition: a few tall rows, much wider than tall (both words on each row).
    assert 3 <= len(lines) <= 7
    assert max(len(ln) for ln in lines) > 3 * len(lines)
    assert "| __(_)" not in out  # not the old small ASCII banner


def test_wordmark_two_tone_is_a_strong_split(monkeypatch) -> None:
    out = _render_truecolor(C.wordmark(), monkeypatch)
    assert "38;2;148;163;184" in out       # FinLex in muted slate #94A3B8
    assert "38;2;94;234;212" in out        # Purple in bright teal #5EEAD4
    # The near-identical primary teal is NOT used for the split anymore.
    assert "38;2;45;212;191" not in out


def test_info_box_has_target_cursor_and_mode_row() -> None:
    info = C.SessionInfo(target="http://127.0.0.1:5078", mode="chat",
                         agent="cashier", model="claude-opus-4-8", provider="anthropic")
    out = _render(C.session_info_panel(info), color=False)
    assert "TARGET: http://127.0.0.1:5078" in out
    assert "█" in out                 # the cursor block
    assert "▌" in out                 # ▌ gold left accent bar
    assert "Chat" in out                   # mode (capitalized)
    assert "cashier" in out and "claude-opus-4-8" in out and "anthropic" in out


def test_info_box_colors_bar_gold_and_fills_surface(monkeypatch) -> None:
    out = _render_truecolor(C.session_info_panel(C.SessionInfo(target="x")), monkeypatch)
    assert "38;2;228;185;91" in out        # gold left bar / mode
    assert "48;2;19;26;38" in out          # surface background #131A26


def test_info_box_empty_target_still_shows_label_and_cursor() -> None:
    out = _render(C.session_info_panel(C.SessionInfo()), color=False)
    assert "TARGET:" in out and "█" in out


def test_hints_line_lists_the_real_commands_bold_keys() -> None:
    out = _render(C.hints_line(), color=False)
    for key, _desc in C.SHORTCUTS:
        assert key in out
    assert "/scan" in out and "/exit" in out and "Ctrl-C" in out


def test_tip_line_has_bullet_tip_and_domain_guidance() -> None:
    out = _render(C.tip_line(), color=False)
    assert "●" in out and "Tip" in out       # ● bullet + Tip
    assert "/scan" in out and "approval" in out   # real guidance
