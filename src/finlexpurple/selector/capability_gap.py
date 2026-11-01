"""Capability-gap detection — report-only (Decision 1).

When the selector meets a technology or vulnerability class the registry has **no
specialist** for, it records a :class:`CapabilityGap`. This is **detection and
reporting only**: a gap is surfaced to the user/report so a *human* can later
author, test, review, and register a specialist through the normal process.

HARD LINE: there is no code path from a gap to a runnable. The system never
generates, writes, registers, or executes a new agent/specialist/module at
runtime. This module only *names* a gap; it cannot fill one.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class CapabilityGap:
    """A technology/vuln class with no registered specialist (a human-authored TODO).

    ``technology`` is the recognized marker (e.g. ``"graphql"``), ``vuln_class``
    the kind of testing it would need, and ``reason`` a short human-facing note.
    """

    technology: str
    vuln_class: str
    reason: str

    def to_dict(self) -> dict[str, Any]:
        """A JSON-serializable mapping for the report surface."""

        return {"technology": self.technology, "vuln_class": self.vuln_class, "reason": self.reason}


# Known technologies/surfaces the current registry does NOT have a specialist for.
# Each maps a lowercase corpus marker -> (technology label, vuln_class). Adding a
# real specialist later is a human task; removing its row here is part of that.
_UNCOVERED: tuple[tuple[str, str, str], ...] = (
    ("graphql", "graphql", "graphql_abuse"),
    ("/grpc", "grpc", "grpc_testing"),
    ("application/grpc", "grpc", "grpc_testing"),
    ("xmlns:soap", "soap", "soap_xxe"),
    ("/soap", "soap", "soap_xxe"),
    ("saml", "saml", "saml_authn"),
    ("websocket", "websocket", "websocket_testing"),
    ("ws://", "websocket", "websocket_testing"),
    ("wss://", "websocket", "websocket_testing"),
    ("ldap://", "ldap", "ldap_injection"),
)


def detect_gaps(corpus: str) -> list[CapabilityGap]:
    """Return a de-duplicated list of capability gaps whose marker appears in ``corpus``.

    ``corpus`` is the same local triage text the selector reads (fingerprint,
    headers, endpoint paths). Matching is plain lowercase substring containment —
    no network, no LLM. Report-only: finding a gap never creates a specialist.
    """

    lowered = corpus.lower()
    gaps: dict[str, CapabilityGap] = {}
    for marker, technology, vuln_class in _UNCOVERED:
        if marker in lowered and technology not in gaps:
            gaps[technology] = CapabilityGap(
                technology=technology,
                vuln_class=vuln_class,
                reason=(
                    f"{technology!r} surface detected but no registered specialist covers "
                    f"{vuln_class!r}; a human must author and register one (never generated at runtime)."
                ),
            )
    return list(gaps.values())
