"""The chat session-screen components render the expected structure in the brand palette."""

from __future__ import annotations

import io

from finlexpurple.tui import components as C
from finlexpurple.tui.theme import make_console


def _render(renderable, *, color: bool, width: int = 72) -> str:
    console = make_console(file=io.StringIO(), no_color=not color, force_terminal=True, width=width)
    console.print(renderable)
    return console.file.getvalue()


def test_banner_panel_contains_the_wordmark_in_a_border() -> None:
    out = _render(C.banner_panel(), color=False)
    assert "| __(_)" in out  # the ASCII wordmark
    assert "autonomous security agent" in out
    assert ("╭" in out and "╰" in out) or ("┌" in out and "└" in out)


def test_session_info_panel_shows_labels_and_values() -> None:
    info = C.SessionInfo(target="http://127.0.0.1:5078", agent="cashier",
                         model="claude-opus-4-8", provider="anthropic", scope="exact")
    out = _render(C.session_info_panel(info), color=False)
    for label in ("Target", "Mode", "Scope", "Agent", "Model"):
        assert label in out
    assert "http://127.0.0.1:5078" in out
    assert "claude-opus-4-8" in out and "anthropic" in out
    assert "session" in out  # the panel title


def test_session_info_panel_omits_absent_fields() -> None:
    out = _render(C.session_info_panel(C.SessionInfo()), color=False)
    assert "Mode" in out  # always present
    assert "Target" not in out and "Agent" not in out and "Model" not in out


def test_hints_line_lists_the_real_commands() -> None:
    out = _render(C.hints_line(), color=False)
    for key, _desc in C.SHORTCUTS:
        assert key in out
    assert "/scan" in out and "/exit" in out and "Ctrl-C" in out


def test_components_colorize_with_the_brand_theme() -> None:
    # With color on, the info panel emits ANSI (gold labels / teal border) via the theme.
    out = _render(C.session_info_panel(C.SessionInfo(target="x")), color=True)
    assert "\x1b[" in out
