"""Direct slash-commands for the chat REPL (chat-only; imports rich + the dispatcher ops).

Typing ``/scan <url>``, ``/run <agent> <url>``, ``/agents``, or ``/verify <bundle>`` runs that
operation **directly**, without a model call — the human drives the tool straight. Each goes
through the exact same registered operation the autonomous dispatcher uses
(:func:`finlexpurple.tui.dispatch.default_operations`), so a typed command and a model-chosen
one are identically safe: the same scope confirmation, egress policy, and approval gate apply.
``/verify`` re-checks an evidence bundle fully offline.

:func:`run_direct_command` returns whether it handled the line, plus a short transcript line to
fold into the conversation history so a later model turn knows what the human ran directly.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from rich.console import Console

from finlexpurple.tui.dispatch import ChatAction, OpContext, default_operations

_USAGE = {
    "/scan": "usage: /scan <url>",
    "/run": "usage: /run <agent> <url>",
    "/verify": "usage: /verify <bundle.json>",
}

#: The direct commands shown in help (``/help``/``/exit`` are handled by the REPL itself).
DIRECT_COMMANDS: tuple[tuple[str, str], ...] = (
    ("/scan <url>", "scan a target (recon, detect, verify)"),
    ("/run <agent> <url>", "run one named agent against a target"),
    ("/agents", "list the named agents"),
    ("/verify <bundle>", "re-verify an evidence bundle offline"),
)


@dataclass(frozen=True)
class DirectResult:
    """Whether the line was a direct command, and a short transcript for the model's history."""

    handled: bool
    transcript: str = ""


def run_direct_command(line: str, *, console: Console, ask: Callable[[str], str]) -> DirectResult:
    """Run a direct slash-command; return ``handled=False`` if ``line`` is not one."""

    parts = line.split()
    cmd = parts[0].lower()
    ops = default_operations()

    if cmd == "/agents":
        result = ops["list_agents"].run(
            OpContext(console=console, ask=ask, action=ChatAction(action="list_agents"))
        )
        console.print("[flp.accent]agents[/]")
        console.print(result.text)
        return DirectResult(True, f"[/agents] {result.summary}")

    if cmd == "/scan":
        if len(parts) < 2:
            console.print(f"[flp.muted]{_USAGE['/scan']}[/]")
            return DirectResult(True)
        result = ops["scan"].run(
            OpContext(console=console, ask=ask, action=ChatAction(action="scan", target=parts[1]))
        )
        return DirectResult(True, f"[/scan {parts[1]}] {result.summary}")

    if cmd == "/run":
        if len(parts) < 3:
            console.print(f"[flp.muted]{_USAGE['/run']}[/]")
            return DirectResult(True)
        result = ops["run_agent"].run(
            OpContext(
                console=console, ask=ask,
                action=ChatAction(action="run_agent", agent=parts[1], target=parts[2]),
            )
        )
        return DirectResult(True, f"[/run {parts[1]} {parts[2]}] {result.summary}")

    if cmd == "/verify":
        if len(parts) < 2:
            console.print(f"[flp.muted]{_USAGE['/verify']}[/]")
            return DirectResult(True)
        return _verify_bundle(parts[1], console=console)

    return DirectResult(False)


def _verify_bundle(path_str: str, *, console: Console) -> DirectResult:
    """Re-verify an evidence bundle offline (same check as the ``verify-bundle`` CLI command)."""

    from finlexpurple.evidence.bundle import BundleFormatError
    from finlexpurple.evidence.verify import verify_bundle

    try:
        text = Path(path_str).read_text(encoding="utf-8")
    except OSError as exc:
        console.print(f"[flp.blocked]could not read bundle:[/] {exc}")
        return DirectResult(True, f"[/verify {path_str}] unreadable")
    try:
        report = verify_bundle(text)
    except BundleFormatError as exc:
        console.print(f"[flp.blocked]not a valid evidence bundle:[/] {exc}")
        return DirectResult(True, f"[/verify {path_str}] invalid")
    for message in report.messages:
        console.print(f"  [flp.muted]{message}[/]")
    if report.ok:
        console.print("[flp.verified]OK[/] [flp.muted]bundle verified[/]")
        return DirectResult(True, f"[/verify {path_str}] OK")
    console.print("[flp.blocked]FAILED[/] [flp.muted]bundle did not verify[/]")
    return DirectResult(True, f"[/verify {path_str}] FAILED")
