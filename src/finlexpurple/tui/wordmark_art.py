"""Generated block art for the wordmark ("FinLex" only), embedded so the chat has no runtime
figlet dependency. "Purple" is rendered alongside as small styled text (not block art).

The font is **ansi_regular** — a solid fill made of exactly one glyph, U+2588 FULL BLOCK (plus
spaces). This is deliberate: the earlier ansi_shadow art mixed FULL BLOCK with the double
box-drawing characters ``═ ║ ╔ ╗ ╚ ╝``, which are East Asian Width "Ambiguous". A terminal
that renders ambiguous characters as two cells wide (while keeping FULL BLOCK at one cell)
gives the rows different widths, so the columns shatter and the wordmark looks garbled in a
real colored terminal — even though the raw character grid is clean. FULL BLOCK is width-1
wherever rich's own bars render (which is everywhere the chat runs), and space is always
width-1, so a FULL-BLOCK-only font keeps every row the same width and renders cleanly. Keep
this art box-drawing-free; the test asserts no ambiguous glyphs sneak back in.
"""

from __future__ import annotations

FINLEX_ART = (
    '███████ ██ ███    ██ ██      ███████ ██   ██',
    '██      ██ ████   ██ ██      ██       ██ ██ ',
    '█████   ██ ██ ██  ██ ██      █████     ███  ',
    '██      ██ ██  ██ ██ ██      ██       ██ ██ ',
    '██      ██ ██   ████ ███████ ███████ ██   ██',
)
