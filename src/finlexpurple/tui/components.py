"""Session-screen rich components for chat (chat-only).

The static screen printed once at the top of a ``chat`` session, laid out like a classic
terminal agent splash: a big two-tone **block wordmark**, a dark **info box** with a gold
left accent bar (TARGET line + mode/model row), a right-aligned **shortcut hints** line, and
a **tip** line — all in the FinLexPurple palette (teal primary, bright teal, gold accent,
muted slate on dark navy). Pure rendering, so each piece can be unit-tested by rendering to
a string; it still prints once in the linear scrollback (no persistent full-screen layout).
"""

from __future__ import annotations

from dataclasses import dataclass

from rich.box import SQUARE
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from finlexpurple.tui import palette

# The shortcut hints shown under the info box and (persistently) in the input toolbar.
SHORTCUTS: tuple[tuple[str, str], ...] = (
    ("/scan", "scan"),
    ("/verify", "bundle"),
    ("/agents", "list"),
    ("/help", "help"),
    ("/exit", "quit"),
    ("Ctrl-C", "cancel"),
)

# A 5-row block font (█) for the big wordmark. Uppercase only; every glyph is 5 columns.
_H = 5
_BLOCK_GLYPHS: dict[str, tuple[str, ...]] = {
    "F": ("█████", "█    ", "████ ", "█    ", "█    "),
    "I": ("█████", "  █  ", "  █  ", "  █  ", "█████"),
    "N": ("█   █", "██  █", "█ █ █", "█  ██", "█   █"),
    "L": ("█    ", "█    ", "█    ", "█    ", "█████"),
    "E": ("█████", "█    ", "████ ", "█    ", "█████"),
    "X": ("█   █", " █ █ ", "  █  ", " █ █ ", "█   █"),
    "P": ("████ ", "█   █", "████ ", "█    ", "█    "),
    "U": ("█   █", "█   █", "█   █", "█   █", "█████"),
    "R": ("████ ", "█   █", "████ ", "█  █ ", "█   █"),
}


def _block_rows(word: str) -> list[str]:
    """Render ``word`` as ``_H`` rows of block glyphs, one space between glyphs."""

    rows = [""] * _H
    for char in word:
        glyph = _BLOCK_GLYPHS[char]
        for r in range(_H):
            rows[r] += glyph[r] + " "
    return [row.rstrip() for row in rows]


@dataclass(frozen=True)
class SessionInfo:
    """What the session-info box shows: the target and the active configuration."""

    target: str | None = None
    mode: str = "chat"
    agent: str | None = None
    model: str | None = None
    provider: str | None = None
    scope: str | None = None


def wordmark() -> Text:
    """The big two-tone block wordmark: FINLEX in primary teal, PURPLE in bright teal."""

    left = _block_rows("FINLEX")
    right = _block_rows("PURPLE")
    text = Text(no_wrap=True)
    for row in range(_H):
        text.append(left[row], style="flp.primary")
        text.append("  ")
        text.append(right[row], style="flp.bright")
        if row < _H - 1:
            text.append("\n")
    return text


def _info_rows(info: SessionInfo) -> Text:
    """The info-box body: a TARGET line with a cursor block, a blank line, and a mode row."""

    body = Text()
    # TARGET line — label muted, value in text, a teal cursor block (invites a target).
    body.append("TARGET: ", style="flp.muted")
    body.append(info.target or "", style="flp.text")
    body.append("█", style="flp.primary")  # █ cursor
    body.append("\n\n")
    # Mode row — the mode word in gold (like their "Pentest"), the model/agent muted.
    body.append(info.mode.capitalize(), style="flp.accent")
    detail = "  ".join(p for p in (info.agent, info.model, info.provider) if p)
    if detail:
        body.append("   ")
        body.append(detail, style="flp.muted")
    return body


def session_info_panel(info: SessionInfo) -> Panel:
    """The dark info box with a gold left accent bar and the TARGET / mode rows."""

    body = _info_rows(info)
    bar = Text("\n".join("▌" for _ in range(body.plain.count("\n") + 1)), style="flp.accent")
    grid = Table.grid(padding=(0, 1))
    grid.add_column(no_wrap=True)  # the gold left accent bar, spanning the body height
    grid.add_column()              # the body
    grid.add_row(bar, body)
    return Panel(
        grid,
        box=SQUARE,
        style=f"{palette.TEXT} on {palette.SURFACE}",  # surface background, like a raised panel
        border_style="flp.border",
        padding=(1, 2),
        expand=True,
    )


def hints_line() -> Text:
    """A single-line shortcut hint: bold keys + muted descriptions (printed right-aligned)."""

    text = Text(no_wrap=False)
    for index, (key, desc) in enumerate(SHORTCUTS):
        if index:
            text.append("   ")
        text.append(key, style="bold flp.text")
        text.append(f" {desc}", style="flp.muted")
    return text


def tip_line() -> Text:
    """The bottom tip: a gold bullet, bold 'Tip', and muted domain guidance."""

    text = Text()
    text.append("● ", style="flp.accent")  # ● bullet
    text.append("Tip", style="bold flp.text")
    text.append(
        " Type a message, or /scan <url> to start a scan — state-changing steps pause "
        "for your approval (y/N).",
        style="flp.muted",
    )
    return text
