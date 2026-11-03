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
import re
from datetime import datetime, timezone
from enum import Enum
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit

from pydantic import BaseModel, ConfigDict, Field


class FindingStatus(str, Enum):
    """The states a finding may hold (decisions.md §6, Layer 3).

    ``REPORTED``/``VERIFIED``/``HUMAN_CONFIRMED`` are the original three. Phase 18
    delegation (Unit 1) adds three precise **non-verified** outcomes of a
    deterministic replay, so the product can say *which* non-verified state a
    finding is in instead of collapsing everything to ``REPORTED``. None of the
    three is a clean bill of health, and only ``VERIFIED`` means independently
    reproduced — reachable solely via ``verifier.status.status_for`` on a
    reproduced replay.
    """

    REPORTED = "reported"
    VERIFIED = "verified"
    HUMAN_CONFIRMED = "human_confirmed"
    # Added in Unit 1 (additive; never produced by Finding.new, only by the verifier):
    INCONCLUSIVE = "inconclusive"      # replayed, but durable impact could not be confirmed
    NOT_REPRODUCED = "not_reproduced"  # replayed and did NOT reproduce (NOT "vulnerability absent")
    BLOCKED = "blocked"                # replay was blocked by the approval gate and did not run


class Severity(str, Enum):
    """Coarse severity ranking used for report aggregation."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


# Versioned, algorithm-tagged id prefixes (Unit 1.2 freeze). The version +
# algorithm prefix is the freeze line: a future v2 scheme ("flp2:...") coexists
# with these, and 0.3.0's pre-freeze bare-hex ids are simply a different, older
# shape. ``evidence_hash`` still binds the exact captured bytes.
FINDING_ID_PREFIX = "flp1:sha256:"
FINGERPRINT_PREFIX = "flpfp1:sha256:"

_DEFAULT_PORTS = {"http": 80, "https": 443}
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.IGNORECASE)
# Query/param names whose VALUES are volatile per request and so are dropped
# from the identity (they would otherwise make the "same" finding look new).
_VOLATILE_PARAMS = frozenset(
    {"csrf", "csrftoken", "csrf_token", "_csrf", "token", "nonce", "_", "ts",
     "timestamp", "time", "sid", "session", "sessionid", "session_id"}
)


def _route_template(path: str) -> str:
    """Collapse concrete resource ids in a URL path to ``{id}`` placeholders.

    Numeric segments and UUIDs become ``{id}`` so ``/orders/123`` and
    ``/orders/456`` are recognized as the same route (the same finding across
    runs even as concrete ids rotate). Conservative on purpose: non-numeric,
    non-UUID words like ``v2`` or ``checkout`` are left untouched.
    """

    out: list[str] = []
    for segment in path.split("/"):
        if segment and (segment.isdigit() or _UUID_RE.match(segment)):
            out.append("{id}")
        else:
            out.append(segment)
    return "/".join(out)


def _normalized_query(query: str) -> str:
    """Sort query keys and drop volatile ones; keep stable key=value pairs."""

    pairs = [
        (key, value)
        for key, value in parse_qsl(query, keep_blank_values=True)
        if key.lower() not in _VOLATILE_PARAMS
    ]
    return urlencode(sorted(pairs))


def _normalize_url_for_id(url: str) -> str:
    """Normalize a URL for identity: lowercase scheme+host, strip default ports,
    route-template the path, sort query keys, drop volatile params.
    """

    parts = urlsplit(url.strip())
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").lower()
    netloc = host
    port = parts.port
    if port is not None and _DEFAULT_PORTS.get(scheme) != port:
        netloc = f"{host}:{port}"
    path = _route_template(parts.path)
    return f"{scheme}://{netloc}{path}?{_normalized_query(parts.query)}"


def _param_names(url: str, payload: str) -> list[str]:
    """Sorted, de-duplicated parameter names from the URL query and the payload.

    Used only for the host-independent fingerprint. Payloads are commonly
    ``name=value``; the name is taken when present, ignoring volatile params.
    """

    names = {key for key, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True)}
    for pair in payload.split("&"):
        if "=" in pair:
            names.add(pair.split("=", 1)[0])
    return sorted(n for n in names if n and n.lower() not in _VOLATILE_PARAMS)


def compute_finding_id(method: str, url: str, payload: str) -> str:
    """Deterministically derive the versioned finding id from method+url+payload.

    Returns ``flp1:sha256:<hex>``. The url is normalized (lowercase scheme+host,
    default ports stripped, path route-templated, query keys sorted, volatile
    params dropped) so re-detecting the same issue yields the same id even as
    concrete resource ids or request nonces rotate. The host is kept, so this is
    the exact per-target instance id; the timestamp and response are excluded.
    """

    canonical = "\n".join([method.upper().strip(), _normalize_url_for_id(url), payload])
    return f"{FINDING_ID_PREFIX}{_sha256(canonical)}"


def compute_fingerprint(
    vulnerability_class: str, url: str, payload: str, *, scope: str = ""
) -> str:
    """Derive the host-independent fingerprint ``flpfp1:sha256:<hex>``.

    Combines the rule key (``vulnerability_class`` today; Unit 1.3 formalizes a
    rule_id catalog that maps to it), the route template, the sorted parameter
    names, and an optional target-scope label (e.g. staging vs prod) — but
    **excludes the host**. So the same flaw on staging and prod shares a
    fingerprint while keeping distinct per-host ``finding_id`` values.
    """

    parts = urlsplit(url.strip())
    canonical = "\n".join(
        [
            vulnerability_class.strip(),
            _route_template(parts.path),
            ",".join(_param_names(url, payload)),
            scope.strip(),
        ]
    )
    return f"{FINGERPRINT_PREFIX}{_sha256(canonical)}"


def route_template(url: str) -> str:
    """Public: the normalized, route-templated path of a URL (for report locations).

    Concrete resource ids become ``{id}`` (see :func:`_route_template`), so a
    structured finding location shows the route, not a single concrete instance.
    """

    return _route_template(urlsplit(url.strip()).path)


def finding_id_slug(finding_id: str) -> str:
    """A filesystem-safe form of a finding id, for evidence/replay/bundle names.

    The id value (``flp1:sha256:<hex>``) contains colons, which are illegal in
    Windows filenames, so on-disk names replace every non ``[A-Za-z0-9._-]``
    character with ``_``. The id itself is unchanged in ``report.json`` and the
    bundle, so value-based lookups (feedback) still match.
    """

    return re.sub(r"[^A-Za-z0-9._-]", "_", finding_id)


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
    # Host-independent matcher (Unit 1.2): the same flaw across staging/prod/runs
    # shares this, while ``finding_id`` stays the exact per-target instance id.
    # Defaulted so a finding dict from before the freeze still deserializes.
    fingerprint: str = ""
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
    # Structured-location and SBOM fields (Unit 1.3), all optional and defaulted
    # so pre-1.3 finding dicts still deserialize. A detector sets ``source_file``
    # /``source_line`` only when a real file anchor exists (never invented), and
    # ``purl`` only for a dependency/container finding with a real package coord.
    source_file: str | None = None
    source_line: int | None = None
    purl: str | None = None
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
        source_file: str | None = None,
        source_line: int | None = None,
        purl: str | None = None,
    ) -> Finding:
        """Create a finding with a deterministic id and the mandatory ``reported`` status.

        ``payload`` is the specific triggering input (the id is derived from
        method+url+payload). The status is hard-coded to ``reported`` here and is
        intentionally **not** a parameter, so a detector cannot create a finding
        that is already "verified". ``source_file``/``source_line`` and ``purl``
        are set only when a real file anchor or package coordinate exists (Unit
        1.3); they are never invented.
        """

        resolved_headers = dict(headers or {})
        return cls(
            finding_id=compute_finding_id(method, url, payload),
            fingerprint=compute_fingerprint(vulnerability_class, url, payload),
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
            source_file=source_file,
            source_line=source_line,
            purl=purl,
        )

    def to_dict(self) -> dict[str, Any]:
        """Return a JSON-serializable mapping (enums as their string values)."""

        return self.model_dump(mode="json")
