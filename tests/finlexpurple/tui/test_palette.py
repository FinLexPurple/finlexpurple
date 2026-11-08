"""The brand palette paints only on a TTY, honors NO_COLOR, and matches the site tokens."""

from __future__ import annotations

import io

from finlexpurple.tui import palette


class _FakeStream(io.StringIO):
    def __init__(self, *, tty: bool) -> None:
        super().__init__()
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def test_palette_values_match_the_website_tokens() -> None:
    # The exact :root hex values from https://finlexpurple.com — the brand is teal/gold,
    # not purple. These are the contract the CLI's colors are derived from.
    assert palette.TEAL == "#2DD4BF"
    assert palette.TEAL_LIGHT == "#5EEAD4"
    assert palette.GOLD == "#E4B95B"
    assert palette.GREEN == "#34D399"
    assert palette.INK == "#0A0E16"
    assert palette.ROLES["primary"].hex == palette.TEAL


def test_truecolor_emits_exact_24bit_sequence(monkeypatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("COLORTERM", "truecolor")
    out = _FakeStream(tty=True)
    painted = palette.paint("x", "primary", stream=out)
    assert painted == "\033[38;2;45;212;191mx\033[0m"  # #2DD4BF -> (45,212,191)


def test_basic16_fallback_when_no_truecolor(monkeypatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("COLORTERM", raising=False)
    out = _FakeStream(tty=True)
    assert palette.paint("x", "primary", stream=out) == "\033[36mx\033[0m"  # teal -> cyan
    assert palette.paint("x", "accent", stream=out) == "\033[33mx\033[0m"   # gold -> yellow


def test_bold_and_dim_modifiers(monkeypatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.delenv("COLORTERM", raising=False)
    out = _FakeStream(tty=True)
    assert palette.paint("x", "primary", stream=out, bold=True).startswith("\033[1m\033[36m")
    assert palette.paint("x", "muted", stream=out, dim=True).startswith("\033[2m\033[90m")


def test_no_color_env_disables_color(monkeypatch) -> None:
    monkeypatch.setenv("NO_COLOR", "")  # mere presence disables, even empty
    out = _FakeStream(tty=True)
    assert palette.use_color(out) is False
    assert palette.paint("x", "primary", stream=out) == "x"


def test_non_tty_never_colorizes(monkeypatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("COLORTERM", "truecolor")
    out = _FakeStream(tty=False)
    assert palette.use_color(out) is False
    assert palette.paint("x", "primary", stream=out) == "x"  # stays clean for pipes


def test_unknown_role_renders_uncolored_not_raising(monkeypatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    out = _FakeStream(tty=True)
    assert palette.paint("x", "no-such-role", stream=out) == "x"
