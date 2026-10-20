"""Slopsquat / hallucinated-dependency detection (Phase 13; Differentiator 6, §25).

Original engineering (not a wrapped tool): detects dependencies that do not
exist or have been attacker-registered — the supply-chain vector created by AI
coding assistants that invent plausible-but-nonexistent package names. Two modes
(§25), always labeled:

* **Online** — a live registry oracle confirms existence; a name the registry
  does not know is a high-confidence hallucinated dependency. The oracle is
  injectable so it can be routed through the egress-checked HTTP layer (§15) in
  deployment and faked in tests.
* **Offline** — no live source, so we only assert what the shipped known-bad
  list supports, at lower confidence; we never claim a name is nonexistent
  without a live check (§25, never overclaim).
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from finlexpurple.detectors.schema import Finding, Severity
from finlexpurple.supplychain import feeds
from finlexpurple.supplychain.mode import (
    Confidence,
    ScanMode,
    labeled_signal,
    labeled_snapshot,
)

# (package_name, ecosystem) -> does it exist in the live registry?
ExistenceOracle = Callable[[str, str], bool]


def _finding(name: str, ecosystem: str, *, message: str, mode: ScanMode, confidence: Confidence) -> Finding:
    return Finding.new(
        vulnerability_class="hallucinated_dependency",
        method="SCA",
        url=f"pkg:{ecosystem}/{name}",
        payload=f"{ecosystem}:{name}",
        response_snapshot=labeled_snapshot(
            {"package": name, "ecosystem": ecosystem, "check": "slopsquat"},
            mode=mode,
            confidence=confidence,
        ),
        expected_signal=labeled_signal(message, mode=mode, confidence=confidence),
        severity=Severity.HIGH,
    )


def check_dependencies(
    dependencies: Iterable[tuple[str, str]],
    *,
    mode: ScanMode,
    oracle: ExistenceOracle | None = None,
) -> list[Finding]:
    """Flag hallucinated / attacker-registered dependencies.

    ``dependencies`` is an iterable of ``(name, ecosystem)``. Online mode needs
    an ``oracle``; a name the oracle reports as nonexistent is flagged
    high-confidence. Offline mode (or online with no oracle) only flags names on
    the shipped known-bad list, at lower confidence.
    """

    online = mode is ScanMode.ONLINE and oracle is not None
    findings: list[Finding] = []
    for name, ecosystem in dependencies:
        key = name.strip().lower()
        if online:
            assert oracle is not None  # narrowed by `online`
            if not oracle(name, ecosystem):
                findings.append(
                    _finding(
                        name,
                        ecosystem,
                        message=f"dependency {name!r} does not exist in the live {ecosystem} registry",
                        mode=ScanMode.ONLINE,
                        confidence=Confidence.HIGH,
                    )
                )
            elif key in feeds.KNOWN_BAD_PACKAGES:
                findings.append(
                    _finding(
                        name,
                        ecosystem,
                        message=f"dependency {name!r} is on the known-bad list (attacker-registered)",
                        mode=ScanMode.ONLINE,
                        confidence=Confidence.HIGH,
                    )
                )
        else:
            # Offline: only assert what the shipped known-bad list supports.
            if key in feeds.KNOWN_BAD_PACKAGES:
                findings.append(
                    _finding(
                        name,
                        ecosystem,
                        message=f"dependency {name!r} matches a shipped known-bad entry",
                        mode=ScanMode.OFFLINE,
                        confidence=Confidence.LOW,
                    )
                )
    return findings
