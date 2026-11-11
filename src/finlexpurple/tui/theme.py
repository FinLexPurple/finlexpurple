"""Rich theme and console factory for the interactive chat (chat-only, imports ``rich``).

The brand styles are derived from the one palette (:mod:`finlexpurple.tui.palette`), so the
chat UI and the plain banner share a single source of truth for the colors. Rich renders
the exact 24-bit hex on a truecolor terminal and automatically downsamples to 256/16 colors
elsewhere, and it honors ``NO_COLOR`` and a non-TTY stream on its own — the same guarantees
the dependency-free palette enforces for the banner.

This module is imported only by the ``chat`` command, so ``rich`` never loads on the hot
path of ``scan`` or any other command.
"""

from __future__ import annotations

from typing import TextIO

from rich.console import Console
from rich.theme import Theme

from finlexpurple.tui import palette

# Brand styles, keyed under an ``flp.*`` namespace so they never collide with rich's
# built-ins. Values are the exact palette hex (+ weight), so truecolor is exact and the
# downsample is rich's problem, not ours.
BRAND_THEME = Theme(
    {
        "flp.primary": palette.TEAL,
        "flp.bright": palette.TEAL_LIGHT,
        "flp.accent": palette.GOLD,
        "flp.success": palette.GREEN,
        "flp.text": palette.TEXT,
        "flp.muted": palette.MUTED,
        "flp.border": palette.LINE_STRONG,
        # Activity-stream statuses (Phase 3): running=gold, done=teal, verified=green,
        # blocked=gold, waiting=muted — the colors the live pipeline cards use.
        "flp.running": f"bold {palette.GOLD}",
        "flp.done": palette.TEAL,
        "flp.verified": f"bold {palette.GREEN}",
        "flp.blocked": f"bold {palette.GOLD}",
        "flp.waiting": palette.MUTED,
        # Key/value chrome: gold labels, body-text values.
        "flp.label": palette.GOLD,
        "flp.value": palette.TEXT,
    }
)


def make_console(
    *,
    file: TextIO | None = None,
    force_terminal: bool | None = None,
    no_color: bool | None = None,
    width: int | None = None,
    color_system: str | None = "auto",
) -> Console:
    """Build a brand-themed rich :class:`Console`.

    Defaults let rich detect the terminal, truecolor support, ``NO_COLOR``, and whether
    the stream is a TTY — matching the banner's rules. The explicit knobs exist for tests
    (force a width, force color on/off) and for the caller to pin a stream. ``highlight`` is
    off so rich never re-colors our content with its automatic syntax highlighter.

    ``color_system`` is passed through to rich. It defaults to ``"auto"`` (rich detects the
    terminal's color depth — the production behavior). A test that needs the exact 24-bit
    brand hex pins ``"truecolor"`` so the output is deterministic on every platform: rich
    ignores ``COLORTERM`` on Windows and would otherwise downsample to 16/256-color there.
    """

    return Console(
        theme=BRAND_THEME,
        file=file,
        force_terminal=force_terminal,
        no_color=no_color,
        width=width,
        color_system=color_system,  # type: ignore[arg-type]  # rich's narrow Literal; we validate by use
        highlight=False,
        emoji=False,
    )
