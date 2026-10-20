"""Fix-mode selection: Agent Fix vs Human Fix (Phase 8; decisions.md §2).

Decides, per run, whether FinLexPurple may generate/apply fixes (``agent``) or
only report findings for a human to act on (``human``). The choice is explicit —
taken from ``--fix-mode`` or, interactively, prompted once per run; a
non-interactive run with no choice defaults to the conservative ``human`` mode
so fixes are never generated without a deliberate decision.

The ``applies_patches`` property is the single switch callers check: when it is
``False`` (``human`` mode), the Phase 15 CodeFix patch path must never be
entered. Keeping that a one-line property makes the "``human`` never patches"
guarantee a trivial, auditable code check rather than scattered conditionals.
"""

from __future__ import annotations

from collections.abc import Callable
from enum import Enum


class FixModeError(ValueError):
    """An unrecognized fix-mode value was supplied."""


class FixMode(str, Enum):
    """The two fix-stage modes (decisions.md §2)."""

    AGENT = "agent"
    HUMAN = "human"

    @property
    def applies_patches(self) -> bool:
        """True only in AGENT mode. Callers must gate the CodeFix path on this."""

        return self is FixMode.AGENT


def _parse(value: str) -> FixMode:
    normalized = value.strip().lower()
    try:
        return FixMode(normalized)
    except ValueError:
        raise FixModeError(
            f"Invalid --fix-mode {value!r}; choose 'agent' or 'human'."
        ) from None


def resolve_fix_mode(
    cli_value: str | None,
    *,
    interactive: bool,
    prompt_fn: Callable[[], str] | None = None,
) -> FixMode:
    """Resolve the run's fix mode from the CLI value, a prompt, or the safe default.

    An explicit ``--fix-mode`` wins. Otherwise, an interactive run prompts once;
    a non-interactive run with no choice defaults to ``human`` (never generate
    fixes without a deliberate decision).
    """

    if cli_value is not None:
        return _parse(cli_value)
    if interactive and prompt_fn is not None:
        return _parse(prompt_fn())
    return FixMode.HUMAN
