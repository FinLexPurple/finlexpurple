"""Phase 8: fix-mode selection (decisions.md §2)."""

from __future__ import annotations

import pytest

from finlexpurple.gates.fix_mode import FixMode, FixModeError, resolve_fix_mode


def test_applies_patches_only_in_agent_mode() -> None:
    assert FixMode.AGENT.applies_patches is True
    # The 'human never patches' guarantee, as a one-line check:
    assert FixMode.HUMAN.applies_patches is False


def test_explicit_cli_value_wins() -> None:
    assert resolve_fix_mode("agent", interactive=False) is FixMode.AGENT
    assert resolve_fix_mode("HUMAN", interactive=True) is FixMode.HUMAN


def test_invalid_value_raises() -> None:
    with pytest.raises(FixModeError, match="Invalid --fix-mode"):
        resolve_fix_mode("auto", interactive=False)


def test_interactive_prompts_once_when_unspecified() -> None:
    calls: list[int] = []

    def prompt() -> str:
        calls.append(1)
        return "agent"

    assert resolve_fix_mode(None, interactive=True, prompt_fn=prompt) is FixMode.AGENT
    assert calls == [1]


def test_non_interactive_without_choice_defaults_to_human() -> None:
    # Conservative: never generate fixes without a deliberate choice.
    assert resolve_fix_mode(None, interactive=False) is FixMode.HUMAN
