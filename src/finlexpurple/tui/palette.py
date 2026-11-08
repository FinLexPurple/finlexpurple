"""The FinLexPurple brand palette for the terminal (dependency-free).

The single source of truth for the brand colors used across the CLI — the banner and
(later) the interactive ``chat`` REPL. The values are the live website palette from
https://finlexpurple.com (its CSS ``:root`` tokens): a dark-navy ground with a **teal**
primary accent and a **gold** secondary accent. (The name notwithstanding, the brand is
not purple — the earlier magenta banner was off-brand and is corrected here.)

Rendering is bound by the same rules the banner has always followed, so colorized output
can never corrupt a pipe or a machine-readable stream:

* **Color only on a real TTY**, and never when ``NO_COLOR`` is set (any value), per
  https://no-color.org.
* **Truecolor only when the terminal advertises it** (``COLORTERM`` is ``truecolor`` or
  ``24bit``); otherwise the nearest 16-color code is used, so the brand still reads on a
  basic terminal.
* This module is pure ANSI + stdlib: no third-party dependency, because it loads on every
  invocation via the banner.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import TextIO

# --- Brand hex values (verbatim from the website :root tokens) -----------------
INK = "#0A0E16"          # --ink: darkest ground
INK_RAISED = "#0D121C"   # --ink-raised
SURFACE = "#131A26"      # --surface
SURFACE_2 = "#1A2332"    # --surface-2
LINE = "#222D3F"         # --line
LINE_STRONG = "#2E3B51"  # --line-strong
TEAL = "#2DD4BF"         # --teal: primary accent
TEAL_LIGHT = "#5EEAD4"   # --teal-light
GREEN = "#34D399"        # --green: success
GOLD = "#E4B95B"         # --gold: secondary accent
TEXT = "#EAF1F5"         # --text
TEXT_2 = "#C3CFDA"       # --text-2
MUTED = "#94A3B8"        # --muted

RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"


@dataclass(frozen=True)
class Color:
    """A brand color: its exact hex plus the nearest basic-16 SGR foreground code."""

    hex: str
    ansi16: str  # SGR foreground code for a non-truecolor terminal


# Semantic roles -> brand color. Everything that paints text names a role, so the
# mapping (not a raw hex) is what callers reach for.
ROLES: dict[str, Color] = {
    "primary": Color(TEAL, "36"),       # teal -> cyan
    "bright": Color(TEAL_LIGHT, "96"),  # light teal -> bright cyan
    "success": Color(GREEN, "32"),      # green
    "accent": Color(GOLD, "33"),        # gold -> yellow
    "text": Color(TEXT, "37"),          # near-white -> white
    "text2": Color(TEXT_2, "37"),       # muted-white -> white
    "muted": Color(MUTED, "90"),        # slate -> bright black
    "border": Color(LINE_STRONG, "90"), # border -> bright black
}


def _is_tty(stream: TextIO) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError, OSError):
        return False


def use_color(stream: TextIO) -> bool:
    """Color only on a real TTY, and never when ``NO_COLOR`` is set (any value)."""

    if "NO_COLOR" in os.environ:
        return False
    return _is_tty(stream)


def supports_truecolor() -> bool:
    """True when the terminal advertises 24-bit color via ``COLORTERM``."""

    return os.environ.get("COLORTERM", "").strip().lower() in ("truecolor", "24bit")


def _hex_to_rgb(value: str) -> tuple[int, int, int]:
    h = value.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def _foreground(color: Color, *, truecolor: bool) -> str:
    """The SGR foreground sequence for a color (24-bit when available, else basic-16)."""

    if truecolor:
        r, g, b = _hex_to_rgb(color.hex)
        return f"\033[38;2;{r};{g};{b}m"
    return f"\033[{color.ansi16}m"


def paint(
    text: str,
    role: str,
    *,
    stream: TextIO,
    bold: bool = False,
    dim: bool = False,
) -> str:
    """Wrap ``text`` in the brand color for ``role`` when ``stream`` supports color.

    Returns ``text`` unchanged on a non-TTY or under ``NO_COLOR`` (so pipes and
    machine-readable output stay clean). Uses truecolor when the terminal advertises it,
    otherwise the nearest basic-16 color, so the brand still reads on a basic terminal.
    An unknown ``role`` renders uncolored rather than raising — color is cosmetic.
    """

    color = ROLES.get(role)
    if color is None or not use_color(stream):
        return text
    prefix = _foreground(color, truecolor=supports_truecolor())
    if bold:
        prefix = BOLD + prefix
    if dim:
        prefix = DIM + prefix
    return f"{prefix}{text}{RESET}"
