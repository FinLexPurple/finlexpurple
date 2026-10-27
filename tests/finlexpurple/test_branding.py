"""The interactive brand banner never corrupts non-interactive output."""

from __future__ import annotations

import io

from finlexpurple import branding
from finlexpurple.cli import _is_top_level_help


class _FakeStream(io.StringIO):
    """A StringIO that can claim to be (or not be) a TTY."""

    def __init__(self, *, tty: bool) -> None:
        super().__init__()
        self._tty = tty

    def isatty(self) -> bool:
        return self._tty


def test_no_banner_on_non_tty_stream() -> None:
    out = _FakeStream(tty=False)
    assert branding.print_banner(out) is False
    assert branding.print_brand_line(out) is False
    assert out.getvalue() == ""  # nothing written to a pipe/redirect


def test_banner_prints_on_tty() -> None:
    out = _FakeStream(tty=True)
    assert branding.print_banner(out) is True
    text = out.getvalue()
    assert "FinLex" not in text or "| __(_)" in text  # the wordmark is present
    assert "autonomous security agent" in text


def test_suppressed_flag_silences_even_on_tty() -> None:
    out = _FakeStream(tty=True)
    assert branding.print_banner(out, suppressed=True) is False
    assert branding.print_brand_line(out, suppressed=True) is False
    assert out.getvalue() == ""


def test_no_color_env_disables_color_but_still_prints(monkeypatch) -> None:
    monkeypatch.setenv("NO_COLOR", "1")
    out = _FakeStream(tty=True)
    assert branding.use_color(out) is False
    branding.print_brand_line(out)
    assert "\033[" not in out.getvalue()  # no ANSI codes
    assert "FinLexPurple" in out.getvalue()


def test_color_used_on_tty_without_no_color(monkeypatch) -> None:
    monkeypatch.delenv("NO_COLOR", raising=False)
    out = _FakeStream(tty=True)
    assert branding.use_color(out) is True
    branding.print_brand_line(out)
    assert "\033[35m" in out.getvalue()  # purple


def test_wordmark_is_pure_ascii_for_legacy_consoles() -> None:
    # Pure ASCII so it encodes on legacy Windows terminals without raising.
    branding._WORDMARK.encode("ascii")
    branding._BRAND_LINE.encode("ascii")


def test_top_level_help_detection() -> None:
    assert _is_top_level_help(["--help"]) is True
    assert _is_top_level_help(["-h"]) is True
    assert _is_top_level_help(["--json-logs", "--help"]) is True  # option before help
    assert _is_top_level_help(["scan", "--help"]) is False        # subcommand first
    assert _is_top_level_help(["--version"]) is False
    assert _is_top_level_help([]) is False
