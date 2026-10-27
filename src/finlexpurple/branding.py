"""Interactive-only brand banner for the CLI.

A small cosmetic polish: a styled wordmark shown on the bare ``finlexpurple``
invocation and ``--help``, and a compact one-line brand at the start of a
``scan``. It is strictly decoration, so it is bound by three rules:

* **Interactive only.** It is written to ``stderr`` and only when that stream is
  a real TTY. A piped, redirected, or otherwise non-interactive ``stderr`` gets
  nothing, so it can never corrupt a script, a grep, ``--version``, JSON logs,
  or any parsed output (all of which go to ``stdout``, which the banner never
  touches).
* **No color unless asked for.** ANSI color is used only on a TTY and never when
  ``NO_COLOR`` is set (per https://no-color.org, the variable's mere presence
  disables color). The wordmark itself is pure ASCII, so it renders on legacy
  Windows terminals without an encoding error.
* **Suppressible.** ``--no-banner`` (and machine-readable modes like
  ``--json-logs``) turn it off explicitly.
"""

from __future__ import annotations

import os
import sys
from typing import TextIO

# Pure-ASCII wordmark (no box-drawing or emoji), so it encodes on every console.
_WORDMARK = r"""
  ___ _      _               ___                _
 | __(_)_ _ | |   _____ __  | _ \_  _ _ _ _ __| |___
 | _|| | ' \| |__/ -_) \ / |  _/ || | '_| '_ \ / -_)
 |_| |_|_||_|____\___/_\_\ |_|  \_,_|_| | .__/_\___|
                                        |_|
"""

_TAGLINE = "local - hardened - autonomous security agent"
_BRAND_LINE = "FinLexPurple - local, hardened autonomous security agent"

# ANSI: magenta/purple for the wordmark, dim for the tagline.
_PURPLE = "\033[35m"
_DIM = "\033[2m"
_RESET = "\033[0m"


def _is_tty(stream: TextIO) -> bool:
    try:
        return bool(stream.isatty())
    except (AttributeError, ValueError, OSError):
        # No isatty (unusual stream), or a closed/detached stream: treat as non-TTY.
        return False


def use_color(stream: TextIO) -> bool:
    """Color only on a real TTY, and never when NO_COLOR is set (any value)."""

    if "NO_COLOR" in os.environ:
        return False
    return _is_tty(stream)


def _should_show(stream: TextIO, *, suppressed: bool) -> bool:
    return not suppressed and _is_tty(stream)


def print_banner(stream: TextIO | None = None, *, suppressed: bool = False) -> bool:
    """Print the full wordmark to ``stream`` (default stderr) if interactive.

    Returns True if it was printed. Does nothing (returns False) when suppressed
    or when the stream is not a TTY, so stdout and any machine-readable output
    stay clean.
    """

    out = stream if stream is not None else sys.stderr
    if not _should_show(out, suppressed=suppressed):
        return False
    if use_color(out):
        body = f"{_PURPLE}{_WORDMARK.rstrip()}{_RESET}\n {_DIM}{_TAGLINE}{_RESET}\n"
    else:
        body = f"{_WORDMARK.rstrip()}\n {_TAGLINE}\n"
    out.write(body + "\n")
    out.flush()
    return True


def print_brand_line(stream: TextIO | None = None, *, suppressed: bool = False) -> bool:
    """Print the compact one-line brand to ``stream`` (default stderr) if interactive.

    Used at the start of a ``scan``; returns True if it was printed.
    """

    out = stream if stream is not None else sys.stderr
    if not _should_show(out, suppressed=suppressed):
        return False
    if use_color(out):
        out.write(f"{_PURPLE}FinLexPurple{_RESET} - local, hardened autonomous security agent\n")
    else:
        out.write(_BRAND_LINE + "\n")
    out.flush()
    return True
