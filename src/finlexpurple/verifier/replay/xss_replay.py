"""XSS replay — headless-browser DOM execution (Phase 11; decisions.md §6, Layer 2).

Verified only if the injected payload actually executes in a real DOM, confirmed
by a headless browser (wrapped as an injected ``browser_runner``), not by the
payload merely appearing in the HTML. When no headless browser is available the
result is ``reported`` (never guessed, never faked). The browser runner is the
one external dependency here; a deployment wires a real headless browser through
the Phase 7 tool layer.
"""

from __future__ import annotations

from collections.abc import Callable

from finlexpurple.detectors.schema import Finding
from finlexpurple.verifier.status import ReplayResult

# (url, injected_payload) -> did the payload execute in the DOM?
BrowserRunner = Callable[[str, str], bool]


def replay(finding: Finding, browser_runner: BrowserRunner | None) -> ReplayResult:
    """Verified iff a headless browser observes the payload executing in the DOM."""

    if browser_runner is None:
        return ReplayResult(None, "XSS replay requires a headless-browser runner; none available.")
    _, _, payload_value = finding.payload.partition("=")
    executed = browser_runner(finding.url, payload_value or finding.payload)
    if executed:
        return ReplayResult(True, f"payload {payload_value!r} executed in a real DOM (headless browser).")
    return ReplayResult(False, f"payload {payload_value!r} did not execute in the DOM.")
