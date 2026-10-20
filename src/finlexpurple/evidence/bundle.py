"""Assemble and (de)serialize a per-finding evidence bundle (Phase 12; §23).

A bundle is a single self-contained JSON file so a third party can carry it to
their own machine and re-verify it with nothing else. Its structure separates
the **payload** (everything that is hashed) from the **envelope** (the content
hash and the signing disclosure):

    {
      "payload": { bundle_schema_version, created_at, finding, replay_log },
      "content_hash": "sha256:<hex over the canonical payload>",
      "signing": { ... how/whether it was signed, disclosed honestly ... }
    }

The hash covers the payload only, so altering any captured evidence changes the
recomputed hash and ``verify-bundle`` fails. The canonical JSON form (sorted
keys, no insignificant whitespace) makes the hash reproducible across machines
and Python versions.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from finlexpurple.detectors.schema import Finding
from finlexpurple.evidence.signing import SigningResult, hash_only

BUNDLE_SCHEMA_VERSION = 1
_HASH_PREFIX = "sha256:"


class BundleFormatError(ValueError):
    """A file is not a well-formed evidence bundle."""


def canonical_json(payload: Any) -> str:
    """Serialize ``payload`` to the one canonical form the hash is computed over.

    Sorted keys, no insignificant whitespace, ASCII-escaped — so the same
    content hashes identically on any machine, regardless of dict insertion
    order or platform.
    """

    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def compute_content_hash(payload: dict[str, Any]) -> str:
    """Return the ``sha256:<hex>`` content hash of a bundle payload."""

    digest = hashlib.sha256(canonical_json(payload).encode("utf-8")).hexdigest()
    return f"{_HASH_PREFIX}{digest}"


def build_payload(finding: Finding, *, created_at: datetime | None = None) -> dict[str, Any]:
    """Build the hashable payload: the finding's evidence plus its replay log."""

    stamp = created_at or datetime.now(timezone.utc)
    return {
        "bundle_schema_version": BUNDLE_SCHEMA_VERSION,
        "created_at": stamp.isoformat(),
        "finding": finding.to_dict(),
        # The deterministic replay account the verifier recorded (Phase 11).
        "replay_log": finding.verification_log or "",
    }


def build_bundle(
    finding: Finding,
    *,
    signing: SigningResult | None = None,
    created_at: datetime | None = None,
) -> dict[str, Any]:
    """Assemble a complete bundle dict for ``finding``.

    The content hash is always computed. ``signing`` is the outcome of a signing
    attempt (see :mod:`finlexpurple.evidence.signing`); when omitted the bundle
    is hash-only, disclosed as such. The signature, when present, is made over
    the content hash, so it is computed here after the hash.
    """

    payload = build_payload(finding, created_at=created_at)
    content_hash = compute_content_hash(payload)
    result = signing if signing is not None else hash_only()
    return {
        "payload": payload,
        "content_hash": content_hash,
        "signing": result.to_dict(),
    }


def dumps_bundle(bundle: dict[str, Any]) -> str:
    """Render a bundle as indented JSON text (readable; the hash uses the canonical form)."""

    return json.dumps(bundle, indent=2, ensure_ascii=True, sort_keys=True) + "\n"


def load_bundle(text: str) -> dict[str, Any]:
    """Parse bundle JSON text, raising :class:`BundleFormatError` if malformed.

    Validates only the top-level shape (``payload``/``content_hash``/``signing``)
    so verification can report a clear structural error rather than a raw
    ``KeyError`` deep inside.
    """

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BundleFormatError(f"bundle is not valid JSON: {exc}") from None
    if not isinstance(data, dict):
        raise BundleFormatError("bundle must be a JSON object.")
    for key in ("payload", "content_hash", "signing"):
        if key not in data:
            raise BundleFormatError(f"bundle is missing the {key!r} field.")
    if not isinstance(data["payload"], dict):
        raise BundleFormatError("bundle 'payload' must be a JSON object.")
    if not isinstance(data["content_hash"], str):
        raise BundleFormatError("bundle 'content_hash' must be a string.")
    if not isinstance(data["signing"], dict):
        raise BundleFormatError("bundle 'signing' must be a JSON object.")
    return data
