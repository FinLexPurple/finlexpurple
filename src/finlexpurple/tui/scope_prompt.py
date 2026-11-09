"""Interactive scope confirmation for the chat agent (chat-only; imports rich).

Before the autonomous agent may scan a target, the human at the keyboard must
confirm — in the chat — that they are authorized to test that exact target. This
renders the SAME scope-boundary disclosure the CLI ``scan`` prints (one source of
truth: :func:`finlexpurple.scope.confirm.scope_boundary_lines`) as a bordered
panel, then reads an explicit yes/no through the injected ``ask``.

Approval is fail-safe: anything but an explicit yes denies, and nothing is
scanned. A confirmation is recorded with a fresh timestamp on every call (each
scan re-attests, never reusing a cached confirmation) and persisted locally
exactly as the CLI records it, so the audit trail is identical whichever front
end confirmed the scope. This is the human's attestation gate for scanning, not a
model decision: the agent can only *propose* a target; it can never confirm its
own scope.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.text import Text

from finlexpurple.scope.confirm import (
    ScopeStorageError,
    save_confirmed_scope,
    scope_boundary_lines,
)
from finlexpurple.scope.models import ScopeDefinition, Target

# Answers (lowercased) that count as confirmation. Anything else — including an
# empty answer — denies, so the safe default is to NOT scan.
_YES = frozenset({"y", "yes"})


def confirm_scope_in_chat(
    target: Target,
    *,
    console: Console,
    ask: Callable[[str], str],
    cache_directory: Path | None = None,
    persist: bool = True,
) -> ScopeDefinition | None:
    """Confirm authorization to test ``target`` in the chat; return the scope or ``None``.

    Renders the scope-boundary disclosure in a panel and asks the human to
    confirm. On an explicit yes it returns a timestamp-confirmed
    :class:`ScopeDefinition` (persisted locally like the CLI unless ``persist`` is
    ``False``); on anything else — a blank, a no, anything but an explicit yes — it
    returns ``None`` so the safe default is to run no scan. A fresh confirmation is
    recorded every call; a cached one is never reused.
    """

    body = Text("\n".join(scope_boundary_lines(target)), style="flp.text")
    console.print(
        Panel(
            body,
            title="scope confirmation",
            title_align="left",
            border_style="flp.blocked",
            padding=(0, 1),
            expand=False,
        )
    )
    answer = ask("confirm you are authorized to test this exact target? [y/N] ").strip().lower()
    if answer not in _YES:
        console.print("[flp.blocked]scope not confirmed[/] [flp.muted]nothing will be scanned[/]")
        return None
    confirmed = ScopeDefinition.for_target(target).confirmed()
    if persist:
        try:
            save_confirmed_scope(confirmed, cache_directory=cache_directory)
        except ScopeStorageError as exc:
            # A persistence failure must not silently discard a genuine confirmation,
            # nor pretend it was saved: proceed with the confirmed scope, disclosing
            # that it was not written locally.
            console.print(f"[flp.muted]scope confirmed (not persisted: {exc})[/]")
            return confirmed
    console.print("[flp.verified]scope confirmed[/] [flp.muted]authorization attested[/]")
    return confirmed
