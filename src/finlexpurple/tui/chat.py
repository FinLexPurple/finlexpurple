"""The interactive ``chat`` REPL loop (chat-only; imports rich + prompt_toolkit).

A linear, scrollback-preserving conversation — **not** a full-screen multi-pane dashboard.
The static session screen (boxed wordmark, session-info box, hints) prints once at the top;
then each turn is: read a line at the styled prompt (with a scrollback-safe bottom toolbar),
show a transient "thinking" status while the turn is handled, and render the reply into the
scrollback. The actual work of a turn is an injected :data:`TurnHandler`, so this loop stays
free of provider/orchestrator wiring (Phase 2 passes a conversational handler; Phase 3 passes
the gated autonomous dispatcher) and is testable with a piped prompt-session.
"""

from __future__ import annotations

from collections.abc import Callable

from prompt_toolkit import PromptSession
from prompt_toolkit.formatted_text import FormattedText
from prompt_toolkit.styles import Style
from rich.console import Console
from rich.markdown import Markdown

from finlexpurple.providers.base import Message
from finlexpurple.tui import palette
from finlexpurple.tui.commands import DIRECT_COMMANDS, run_direct_command
from finlexpurple.tui.components import (
    SHORTCUTS,
    SessionInfo,
    hints_line,
    session_info_panel,
    tip_line,
    wordmark,
)

# Given the user's line and the conversation so far, produce the assistant's reply text.
# Injected so the loop never imports a provider or the orchestrator directly.
TurnHandler = Callable[[str, "list[Message]"], str]

_EXIT_COMMANDS = ("/exit", "/quit")


def _prompt_style(*, color: bool) -> Style | None:
    """The prompt + bottom-toolbar style in the brand palette, or ``None`` under NO_COLOR."""

    if not color:
        return None
    return Style.from_dict(
        {
            "prompt": f"{palette.TEAL} bold",
            "bottom-toolbar": f"{palette.MUTED} bg:{palette.SURFACE}",
            "bottom-toolbar.key": palette.GOLD,
        }
    )


def _prompt_message() -> FormattedText:
    return FormattedText([("class:prompt", "flp › ")])  # "flp ›"


def _bottom_toolbar() -> FormattedText:
    parts: list[tuple[str, str]] = []
    for index, (key, desc) in enumerate(SHORTCUTS):
        if index:
            parts.append(("", "  "))
        parts.append(("class:bottom-toolbar.key", key))
        parts.append(("class:bottom-toolbar", f" {desc}"))
    return FormattedText(parts)


def _print_session_screen(console: Console, info: SessionInfo) -> None:
    console.print(wordmark())
    console.print()
    console.print(session_info_panel(info))
    console.print(hints_line(), justify="right")
    console.print()
    console.print(tip_line())
    console.print()


def _print_help(console: Console) -> None:
    console.print("[flp.accent]Commands[/]")
    for key, desc in DIRECT_COMMANDS:
        console.print(f"  [flp.accent]{key:20}[/]  [flp.muted]{desc}[/]")
    console.print(f"  [flp.accent]{'/help':20}[/]  [flp.muted]show this help[/]")
    console.print(f"  [flp.accent]{'/exit':20}[/]  [flp.muted]quit[/]")
    console.print(
        "[flp.muted]Or just type a message — the agent decides what to run, confirming scope "
        "and pausing for your approval on anything state-changing.[/]"
    )


def _render_turn(console: Console, handler: TurnHandler, line: str, history: list[Message]) -> None:
    """Handle one user turn: the handler owns in-turn progress (its activity stream), then
    the reply is rendered as markdown into the scrollback.

    The handler is NOT wrapped in a status spinner here: a handler that shows a live
    activity stream (the autonomous dispatcher) owns the single live region for the turn,
    and rich permits only one live display at a time.
    """

    reply = handler(line, list(history))
    history.append(Message(role="user", content=line))
    history.append(Message(role="assistant", content=reply))
    console.print()
    console.print(Markdown(reply))
    console.print()


def _no_input(_prompt: str) -> str:
    """Default human-input function: denies (fail-safe when a caller wires none)."""

    return ""


def run_chat(
    *,
    console: Console,
    handler: TurnHandler,
    info: SessionInfo,
    session: PromptSession,
    ask: Callable[[str], str] = _no_input,
    color: bool = True,
) -> int:
    """Run the chat REPL until the user exits. Returns a process exit code (0).

    ``ask`` is the human-input function the direct slash-commands (and, through the handler,
    the autonomous operations) use for scope confirmation and the approval gate.
    """

    _print_session_screen(console, info)
    style = _prompt_style(color=color)
    history: list[Message] = []
    while True:
        try:
            line = session.prompt(_prompt_message(), bottom_toolbar=_bottom_toolbar, style=style)
        except EOFError:  # Ctrl-D: end the session
            break
        except KeyboardInterrupt:  # Ctrl-C at the prompt: cancel this line, keep going
            console.print("[flp.muted]^C[/]")
            continue
        line = line.strip()
        if not line:
            continue
        if line in _EXIT_COMMANDS:
            break
        if line == "/help":
            _print_help(console)
            continue
        if line.startswith("/"):
            result = run_direct_command(line, console=console, ask=ask)
            if result.handled:
                # Fold a short transcript into history so a later model turn knows what ran.
                if result.transcript:
                    history.append(Message(role="user", content=result.transcript))
                continue
            console.print(f"[flp.muted]unknown command {line!r}; try /help[/]")
            continue
        _render_turn(console, handler, line, history)
    console.print("[flp.muted]bye[/]")
    return 0
