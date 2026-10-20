"""The universal ``Finding`` schema — the one data contract every module emits.

Phase 7 (architecture.md), implementing decisions.md §6 (structured finding
capture). This is the single most important data structure in the system: every
later module — web detectors, the AI-agent/MCP module, the wrapped supply-chain
and container scanners, and the financial agents — produces findings in exactly
this shape, and nothing downstream accepts anything else.

Two integrity properties are enforced here, not left to callers:

* ``finding_id`` is **deterministic** — a hash of method+url+payload — so
  re-running a detector against the same endpoint produces the *same* finding
  id, never a random one. This is what lets a finding be recognized as "the same
  finding" across runs.
* A finding is **always created with status ``reported``**. Only Phase 11
  (verification) or Phase 8/11 human confirmation may move it to ``verified`` or
  ``human_confirmed``; a detector never sets the status itself. The
  ``Finding.new`` factory is the detector-facing entry point and hard-codes the
  initial status, so a detector cannot accidentally (or deliberately) create a
  pre-"verified" finding.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class FindingStatus(str, Enum):
    """The three states a finding may hold (decisions.md §6, Layer 3)."""

    REPORTED = "reported"
    VERIFIED = "verified"
    HUMAN_CONFIRMED = "human_confirmed"


class Severity(str, Enum):
    """Coarse severity ranking used for report aggregation."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def compute_finding_id(method: str, url: str, payload: str) -> str:
    """Deterministically derive a finding id from method+url+payload.

    Uses a newline-delimited canonical form so the three parts cannot run
    together ambiguously, then SHA-256. Identical inputs always yield an
    identical id; the id deliberately excludes the timestamp and response so
    that re-detecting the same issue is recognized as the same finding.
    """

    return _sha256("\n".join([method.upper().strip(), url.strip(), payload]))


def compute_evidence_hash(
    method: str,
    url: str,
    headers: dict[str, str],
    body: str | None,
    response_snapshot: str | None,
) -> str:
    """Hash the full request/response pair, for later replay-integrity checks.

    The verifier (Phase 11) and the signed evidence bundle (Phase 12) use this
    to confirm that a replay reproduced the same evidence the detector captured.
    Headers are sorted so the hash is stable regardless of insertion order.
    """

    canonical = json.dumps(
        {
            "method": method.upper().strip(),
            "url": url.strip(),
            "headers": {k: headers[k] for k in sorted(headers)},
            "body": body,
            "response_snapshot": response_snapshot,
        },
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return _sha256(canonical)


class Finding(BaseModel):
    """A single, structured, replayable finding.

    Fields mirror decisions.md §6 Layer 1 (structured capture). ``finding_id``
    and ``evidence_hash`` are derived, not free-form; prefer the ``Finding.new``
    factory, which computes them and forces the initial status. The model stays
    mutable so Phase 11 can update ``status``/attach verification output, but a
    detector should only ever call ``new``.
    """

    model_config = ConfigDict(extra="forbid")

    finding_id: str
    vulnerability_class: str
    method: str
    url: str
    # The exact triggering payload, stored so the finding is replayable (§6 Layer 1).
    payload: str
    headers: dict[str, str] = Field(default_factory=dict)
    body: str | None = None
    response_snapshot: str | None = None
    expected_signal: str = ""
    evidence_hash: str
    status: FindingStatus = FindingStatus.REPORTED
    severity: Severity = Severity.MEDIUM
    discovered_at: datetime
    # Populated from Phase 18 onward with the named agent that produced it.
    agent: str | None = None
    # Set by the Phase 11 verification engine: a deterministic record of the
    # replay attempt. None until verification runs.
    verification_log: str | None = None

    @classmethod
    def new(
        cls,
        *,
        vulnerability_class: str,
        method: str,
        url: str,
        payload: str,
        headers: dict[str, str] | None = None,
        body: str | None = None,
        response_snapshot: str | None = None,
        expected_signal: str = "",
        severity: Severity = Severity.MEDIUM,
        agent: str | None = None,
        discovered_at: datetime | None = None,
    ) -> Finding:
        """Create a finding with a deterministic id and the mandatory ``reported`` status.

        ``payload`` is the specific triggering input (the id is derived from
        method+url+payload). The status is hard-coded to ``reported`` here and is
        intentionally **not** a parameter, so a detector cannot create a finding
        that is already "verified".
        """

        resolved_headers = dict(headers or {})
        return cls(
            finding_id=compute_finding_id(method, url, payload),
            vulnerability_class=vulnerability_class,
            method=method.upper().strip(),
            url=url.strip(),
            payload=payload,
            headers=resolved_headers,
            body=body,
            response_snapshot=response_snapshot,
            expected_signal=expected_signal,
            evidence_hash=compute_evidence_hash(
                method, url, resolved_headers, body, response_snapshot
            ),
            status=FindingStatus.REPORTED,
            severity=severity,
            discovered_at=discovered_at or datetime.now(timezone.utc),
            agent=agent,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable mapping (enums as their string values)."""

        return self.model_dump(mode="json")
