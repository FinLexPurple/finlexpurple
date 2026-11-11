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


def test_wordmark_is_thick_block_finlex_with_purple_companion() -> None:
    out = _render(C.wordmark(), color=False, width=120)
    lines = [ln for ln in out.splitlines() if ln.strip()]
    # FinLex is a solid filled block font (█), not thin hollow outlines.
    assert "█" in out
    assert 5 <= len(lines) <= 7            # the block is a few rows tall, one line of lettering
    assert max(len(ln) for ln in lines) <= 80  # FinLex-only block fits comfortably one line
    # "Purple" is the small letter-spaced companion alongside.
    assert "P U R P L E" in out
    assert "| __(_)" not in out            # not the old small ASCII banner
    # The art must stay free of East-Asian-Ambiguous box-drawing glyphs: those render
    # two cells wide in some terminals and shatter the columns (the colored-terminal garble).
    assert not set(out) & set("═║╔╗╚╝╦╠╣╬╦╩╬"), "wordmark must stay box-drawing-free"


def test_wordmark_two_tone_is_a_strong_split(monkeypatch) -> None:
    out = _render_truecolor(C.wordmark(), monkeypatch)
    assert "38;2;13;148;136" in out        # FinLex in deep teal #0D9488 (dimmer)
    assert "1;38;2;234;241;245" in out     # Purple companion: bold + bright near-white #EAF1F5


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
