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


def test_wordmark_is_big_block_lettering() -> None:
    out = _render(C.wordmark(), color=False)
    assert "█" in out                 # █ block cells
    assert out.count("\n") >= 4            # multi-row block font
    # Rendered as blocks, not the old small ASCII banner.
    assert "| __(_)" not in out


def test_wordmark_two_tone_uses_primary_and_bright_teal(monkeypatch) -> None:
    out = _render_truecolor(C.wordmark(), monkeypatch)
    assert "38;2;45;212;191" in out        # FINLEX in primary teal #2DD4BF
    assert "38;2;94;234;212" in out        # PURPLE in bright teal #5EEAD4


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
