"""Release identity: the cosmetic codename scheme (Phase 20; decisions.md §16).

Semantic versioning stays the one canonical version identifier. Alongside it,
each release also carries a **codename** drawn from a tradecraft-themed word pool
(words that describe what the agents do). The codename is **cosmetic** — it
appears in ``--version`` output, the changelog, and release notes, and is
**never** parsed or used in place of the semver number.
"""

from __future__ import annotations

from finlexpurple import __version__

# Tradecraft-themed pool (decisions.md §16). Order defines the release sequence:
# the first real release (0.1.0) is "Recon", 0.2.0 "Vantage", and so on.
RELEASE_CODENAMES: tuple[str, ...] = (
    "Recon",
    "Vantage",
    "Foothold",
    "Pivot",
    "Overwatch",
    "Breach",
    "Blindside",
    "Checkmate",
)


def codename_for(version: str) -> str:
    """Return the cosmetic codename for a semver string (never parsed back).

    Pre-1.0 the codename tracks the minor version: 0.1.x -> Recon, 0.2.x ->
    Vantage, ... wrapping if the pool is exhausted. A malformed version falls
    back to the first codename rather than raising — the codename is cosmetic.
    """

    parts = version.split(".")
    try:
        minor = int(parts[1]) if len(parts) > 1 else 0
    except ValueError:
        minor = 0
    index = max(minor - 1, 0) % len(RELEASE_CODENAMES)
    return RELEASE_CODENAMES[index]


def version_line() -> str:
    """The ``--version`` string: the canonical semver plus the cosmetic codename."""

    return f"{__version__} ({codename_for(__version__)})"
