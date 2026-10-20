"""Payment-SDK typosquat detection (Phase 13; Differentiator 7, §25).

Original engineering: detects fake JazzCash/Easypaisa/Stripe/Paysafe-style SDK
packages — payment SDKs are a high-value typosquat target specific to our
fintech focus. A dependency whose name is a near-miss of a known legitimate
payment SDK (but not an exact match) is flagged. Online mode can additionally
confirm the impostor is actually registered (high confidence); offline mode
relies on the edit-distance heuristic alone (lower confidence, §25).
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

# (name, ecosystem) -> is this impostor name actually registered in the live registry?
ExistenceOracle = Callable[[str, str], bool]

# A name within this edit distance of a known SDK (but not equal) is a typosquat.
_MAX_EDIT_DISTANCE = 2


def levenshtein(a: str, b: str) -> int:
    """Classic edit distance (insert/delete/substitute), small and dependency-free."""

    if a == b:
        return 0
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, start=1):
        current = [i]
        for j, cb in enumerate(b, start=1):
            cost = 0 if ca == cb else 1
            current.append(min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost))
        previous = current
    return previous[-1]


def _nearest_sdk(name: str) -> tuple[str, int] | None:
    """The closest known payment SDK to ``name`` and its distance, if any is close."""

    best: tuple[str, int] | None = None
    for sdk in feeds.KNOWN_PAYMENT_SDKS:
        distance = levenshtein(name, sdk)
        if distance == 0:
            return None  # exact match — this IS the legitimate SDK, not a squat
        if distance <= _MAX_EDIT_DISTANCE and (best is None or distance < best[1]):
            best = (sdk, distance)
    return best


def check_dependencies(
    dependencies: Iterable[tuple[str, str]],
    *,
    mode: ScanMode,
    oracle: ExistenceOracle | None = None,
) -> list[Finding]:
    """Flag dependencies whose names impersonate a known payment SDK."""

    findings: list[Finding] = []
    for name, ecosystem in dependencies:
        key = name.strip().lower()
        if key in feeds.KNOWN_PAYMENT_SDKS:
            continue
        nearest = _nearest_sdk(key)
        if nearest is None:
            continue
        sdk, distance = nearest
        online = mode is ScanMode.ONLINE and oracle is not None
        # Online: a registered impostor is high-confidence; offline: heuristic only.
        if online:
            assert oracle is not None
            registered = oracle(name, ecosystem)
            confidence = Confidence.HIGH if registered else Confidence.MEDIUM
            effective_mode = ScanMode.ONLINE
            extra = " and is registered in the live registry" if registered else ""
        else:
            confidence = Confidence.LOW
            effective_mode = ScanMode.OFFLINE
            extra = ""
        findings.append(
            Finding.new(
                vulnerability_class="payment_sdk_typosquat",
                method="SCA",
                url=f"pkg:{ecosystem}/{name}",
                payload=f"{ecosystem}:{name}",
                response_snapshot=labeled_snapshot(
                    {
                        "package": name,
                        "ecosystem": ecosystem,
                        "impersonates": sdk,
                        "edit_distance": distance,
                        "check": "payment_sdk_typosquat",
                    },
                    mode=effective_mode,
                    confidence=confidence,
                ),
                expected_signal=labeled_signal(
                    f"{name!r} resembles payment SDK {sdk!r} (edit distance {distance}){extra}",
                    mode=effective_mode,
                    confidence=confidence,
                ),
                severity=Severity.HIGH,
            )
        )
    return findings
