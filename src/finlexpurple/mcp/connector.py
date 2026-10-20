"""Interfaces for driving a target AI agent / MCP integration (Phase 9).

The offensive testers operate against an :class:`AgentConnector` — a minimal,
injectable interface for sending a message (or a message under an
attacker-controlled tool description) to the *target* agent and reading its
reply. Real MCP/agent clients implement this; tests implement a synthetic one.
Decoupling the testers from any concrete client keeps them small, deterministic,
and verifiable without live infrastructure.

The exfiltration oracle judges success only by an out-of-band
:class:`Canary` — a callback observed outside the agent's reply — never by what
the agent *says*. ``LocalCanary`` is an in-process reference implementation for
tests; a real deployment uses a network listener implementing the same
protocol.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol, runtime_checkable


@runtime_checkable
class AgentConnector(Protocol):
    """Minimal interface to the target agent under test."""

    def ask(self, message: str) -> str:
        """Send ``message`` to the target agent and return its reply text."""
        ...

    def ask_with_tool(self, tool_description: str, message: str) -> str:
        """Send ``message`` with an (attacker-controlled) tool description in scope."""
        ...


@runtime_checkable
class Canary(Protocol):
    """An out-of-band callback oracle for confirming true exfiltration."""

    @property
    def token(self) -> str:
        """A unique token embedded in the probe; a callback bearing it proves exfil."""
        ...

    def triggered(self) -> bool:
        """True only if the token-bearing callback was actually observed out-of-band."""
        ...


@dataclass
class LocalCanary:
    """In-process reference :class:`Canary` for tests and local use.

    ``trigger`` simulates the out-of-band callback a real listener would observe;
    ``triggered`` reports whether it happened. The agent's own reply never sets
    this — only an actual callback does.
    """

    token: str
    _triggered: bool = False

    def trigger(self) -> None:
        self._triggered = True

    def triggered(self) -> bool:
        return self._triggered
