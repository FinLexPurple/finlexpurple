"""Reusable rich renderables for the chat session screen (chat-only).

Pure rendering: each function returns a rich renderable built from the brand theme, so
they can be unit-tested by rendering to a string. The session screen at the start of a
chat is a **boxed wordmark panel**, a **session-info box** (gold labels, body values), and
a **shortcut hints** line — the static chrome shown once, in linear scrollback (never a
persistent full-screen layout).
"""

from __future__ import annotations

from dataclasses import dataclass

from rich.align import Align
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from finlexpurple import branding

# The shortcut hints shown in the session screen and (persistently) in the input
# toolbar. Slash-commands plus cancel — our real controls, not a pane switcher.
SHORTCUTS: tuple[tuple[str, str], ...] = (
    ("/scan", "run a scan"),
    ("/verify", "re-verify a bundle"),
    ("/agents", "list agents"),
    ("/help", "commands"),
    ("/exit", "quit"),
    ("Ctrl-C", "cancel"),
)


@dataclass(frozen=True)
class SessionInfo:
    """What the session-info box shows: the target and the active configuration."""

    target: str | None = None
    mode: str = "chat"
    agent: str | None = None
    model: str | None = None
    provider: str | None = None
    scope: str | None = None


def banner_panel() -> Panel:
    """The brand wordmark in a bordered panel — the chat's boxed header."""

    wordmark = Text(branding._WORDMARK.strip("\n"), style="flp.primary")
    tagline = Text(branding._TAGLINE, style="flp.muted")
    body = Text.assemble(wordmark, "\n", tagline)
    return Panel(
        Align.left(body),
        border_style="flp.border",
        padding=(1, 2),
        expand=False,
    )


def session_info_panel(info: SessionInfo) -> Panel:
    """The session-info box: gold labels, body-text values, in a bordered panel."""

    rows: list[tuple[str, str]] = [("Mode", info.mode)]
    if info.target:
        rows.insert(0, ("Target", info.target))
    if info.scope:
        rows.append(("Scope", info.scope))
    if info.agent:
        rows.append(("Agent", info.agent))
    if info.provider or info.model:
        rows.append(("Model", " ".join(p for p in (info.model, info.provider) if p)))

    grid = Table.grid(padding=(0, 2))
    grid.add_column(justify="left", style="flp.label", no_wrap=True)
    grid.add_column(justify="left", style="flp.value")
    for label, value in rows:
        grid.add_row(label, value)

    return Panel(grid, title="session", title_align="left",
                 border_style="flp.border", padding=(0, 1), expand=False)


def hints_line() -> Text:
    """A single-line shortcut hint for the session screen (muted keys, muted text)."""

    text = Text(no_wrap=False)
    for index, (key, desc) in enumerate(SHORTCUTS):
        if index:
            text.append("   ")
        text.append(key, style="flp.accent")
        text.append(f" {desc}", style="flp.muted")
    return text
