"""The interactive approval-gate prompt for chat (chat-only; imports rich).

The approval gate is the safety spine. When a state-changing action needs approval, the
gate calls a ``confirm_fn`` to ask a **human** — this module renders that question in the
chat and reads the human's yes/no. It is purely the asking UI: it never weakens the gate.
The gate itself still guarantees that hard-gated categories (banking/teller/vault/mcp) can
never be config-allowed and pause when no human is present, and the **autonomous agent can
only propose** a gated action — approval comes from the person at the keyboard, never from
the model.

The input is injected (``ask``) so the confirmer is testable with a scripted answer; the
chat command wires ``ask`` to a prompt_toolkit yes/no prompt.
"""

from __future__ import annotations

from collections.abc import Callable

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# Answers (lowercased) that count as approval. Anything else — including empty — denies,
# so the safe default is to NOT approve.
_YES = frozenset({"y", "yes"})


def make_gate_confirm(console: Console, ask: Callable[[str], str]) -> Callable[[str], bool]:
    """Build a gate ``confirm_fn`` that asks the human in the chat and returns their decision.

    ``ask(prompt)`` returns the human's raw answer; approval requires an explicit yes, so a
    blank or anything else denies (fail-safe). The decision is echoed so the scrollback
    shows what was approved or denied.
    """

    def confirm(prompt: str) -> bool:
        panel = Panel(
            Text(prompt, style="flp.text"),
            title="approval required",
            title_align="left",
            border_style="flp.blocked",
            padding=(0, 1),
            expand=False,
        )
        console.print(panel)
        answer = ask("approve this action? [y/N] ").strip().lower()
        approved = answer in _YES
        if approved:
            console.print("[flp.verified]approved[/] [flp.muted]by operator[/]")
        else:
            console.print("[flp.blocked]denied[/] [flp.muted]action not run[/]")
        return approved

    return confirm
