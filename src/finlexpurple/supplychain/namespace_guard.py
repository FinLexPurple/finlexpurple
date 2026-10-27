"""Dependency-confusion guard for our own package namespace (Phase 20; §28 #2).

Most of the supply-chain package scans the *target's* dependencies. This module
protects **our own** release instead. Dependency-confusion (a.k.a. namespace
squatting) attacks publish a malicious package under a name a victim's installer
might resolve by mistake — here, the ``finlexpurple`` name itself or anything
under the ``finlexpurple-*`` / ``finlexpurple_*`` prefix we reserve for
first-party plugins.

The guard enumerates installed distributions, keeps only those inside our
namespace, and flags any that is either (a) not one of the distributions we
actually publish, or (b) missing our first-party provenance in its metadata. A
registered first-party package is silent; anything else surfaces a warning so a
squatted or confused install is caught rather than trusted. The check is pure
over its inputs so it is unit-testable without touching the real environment,
with a thin wrapper that feeds it ``importlib.metadata``.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# The distributions we actually publish. A package inside our namespace that is
# not on this list is suspicious until it is explicitly registered here — the
# allow-list is the point of control, so fail closed on the unknown.
KNOWN_FIRST_PARTY: frozenset[str] = frozenset({"finlexpurple"})

# Prefixes reserved for first-party plugins; a package using one must still be a
# KNOWN_FIRST_PARTY entry to be trusted.
NAMESPACE_PREFIXES: tuple[str, ...] = ("finlexpurple-", "finlexpurple_")

# Markers of our first-party provenance, matched case-insensitively against the
# distribution's Author / Author-email / Home-page / Project-URL metadata.
_PROVENANCE_MARKERS: tuple[str, ...] = (
    "finlexpurple",
    "github.com/finlexpurple",
)


@dataclass(frozen=True)
class NamespaceWarning:
    """One installed distribution in our namespace that could not be trusted."""

    distribution: str
    reason: str


def canonical_name(name: str) -> str:
    """Normalize a distribution name per PEP 503 (case/`-`/`_`/`.` insensitive)."""

    normalized = name.strip().lower()
    for char in ("_", "."):
        normalized = normalized.replace(char, "-")
    return normalized


def in_our_namespace(name: str) -> bool:
    """True if ``name`` is our distribution or under a reserved namespace prefix."""

    canonical = canonical_name(name)
    if canonical == "finlexpurple":
        return True
    # Compare against canonicalized prefixes so finlexpurple_foo == finlexpurple-foo.
    return any(canonical.startswith(canonical_name(prefix)) for prefix in NAMESPACE_PREFIXES)


def _has_first_party_provenance(metadata: Mapping[str, str]) -> bool:
    haystack = " ".join(
        str(metadata.get(key, "") or "")
        for key in ("Author", "Author-email", "Home-page", "Project-URL")
    ).lower()
    return any(marker in haystack for marker in _PROVENANCE_MARKERS)


def audit_namespace(
    distributions: Iterable[tuple[str, Mapping[str, str]]],
) -> list[NamespaceWarning]:
    """Flag installed namespace distributions that are unregistered or unsigned-by-metadata.

    ``distributions`` is an iterable of ``(name, metadata)`` pairs. A package
    outside our namespace is ignored; one inside it is warned about when it is
    not a registered first-party distribution, or when it is but its metadata
    lacks our provenance markers (a sign its name was reused by someone else).
    """

    warnings: list[NamespaceWarning] = []
    for name, metadata in distributions:
        if not in_our_namespace(name):
            continue
        canonical = canonical_name(name)
        if canonical not in KNOWN_FIRST_PARTY:
            warnings.append(
                NamespaceWarning(
                    name,
                    "package occupies the finlexpurple namespace but is not a "
                    "registered first-party distribution (possible dependency "
                    "confusion / namespace squat).",
                )
            )
            continue
        if not _has_first_party_provenance(metadata):
            warnings.append(
                NamespaceWarning(
                    name,
                    "registered first-party distribution is missing our provenance "
                    "metadata (author/home-page/project-url) — the installed copy "
                    "may not be ours.",
                )
            )
    return warnings


def audit_environment() -> list[NamespaceWarning]:
    """Run :func:`audit_namespace` over the currently installed distributions."""

    from importlib import metadata as importlib_metadata
    from typing import Any

    pairs: list[tuple[str, Mapping[str, str]]] = []
    for dist in importlib_metadata.distributions():
        # dist.metadata is a case-insensitive email.message-style header map; its
        # typeshed Protocol does not declare .get, so read it through Any.
        md: Any = dist.metadata
        name = md.get("Name") or (dist.name or "")
        if not name:
            continue
        meta = {
            key: (md.get(key) or "")
            for key in ("Author", "Author-email", "Home-page", "Project-URL")
        }
        pairs.append((name, meta))
    warnings = audit_namespace(pairs)
    for warning in warnings:
        logger.warning("Namespace guard: %s — %s", warning.distribution, warning.reason)
    return warnings
