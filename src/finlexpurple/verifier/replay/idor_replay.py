"""IDOR replay — two-session diff (Phase 11; decisions.md §6, Layer 2).

Requests the same object under two independent sessions (an owner and a second,
low-privilege session). It is verified only if the second session genuinely
receives the owner's object (identical, non-empty 200 body) — real unauthorized
access, not a superficial difference. Deterministic; no LLM involved.
"""

from __future__ import annotations

from finlexpurple.detectors.prober import Prober
from finlexpurple.detectors.schema import Finding
from finlexpurple.verifier.status import ReplayResult

Sessions = tuple[dict[str, str], dict[str, str]]


def replay(finding: Finding, prober: Prober | None, sessions: Sessions | None) -> ReplayResult:
    """Verified iff a second session receives the first session's object."""

    if prober is None or sessions is None:
        return ReplayResult(None, "IDOR replay requires a prober and two sessions; not provided.")
    owner_headers, other_headers = sessions
    param = finding.payload.split("=", 1)[0]
    object_id = "1"
    owner = prober.request(finding.method, finding.url, params={param: object_id}, headers=owner_headers)
    other = prober.request(finding.method, finding.url, params={param: object_id}, headers=other_headers)
    if (
        owner.status_code == 200
        and other.status_code == 200
        and owner.text.strip()
        and owner.text == other.text
    ):
        return ReplayResult(
            True,
            "a second, low-privilege session received the owner's object (unauthorized access confirmed).",
        )
    return ReplayResult(False, "the second session did not receive the owner's object.")
