"""Assemble and (de)serialize a per-finding evidence bundle (Phase 12; §23).

A bundle is a single self-contained JSON file so a third party can carry it to
their own machine and re-verify it with nothing else.

**Two on-disk formats; ``verify-bundle`` accepts both forever (Unit 1.1).**

*Legacy ``flp-bundle/v0``* — what 0.3.0 shipped. The hash is recomputed by
re-serializing the payload to canonical JSON:

    {
      "payload": { bundle_schema_version, created_at, finding, replay_log },
      "content_hash": "sha256:<hex over the canonical payload>",
      "signing": { ... how/whether it was signed, disclosed honestly ... }
    }

These bundles are already on users' disks, so :func:`verify_bundle` keeps
accepting them **exactly as-is** and they are never rewritten.

*Current ``flp-bundle/v1``* — a DSSE envelope around an in-toto Statement v1.
The signed/hashed object is stored as the **exact serialized bytes** (base64),
and verification hashes *those stored bytes* — it never re-serializes, so a
future ``json``/library change can never break an old signature:

    {
      "bundle_format": "flp-bundle/v1",
      "dsse": {
        "payloadType": "application/vnd.in-toto+json",
        "payload": "<base64 of the exact in-toto Statement bytes>",
        "signatures": [ { "sig": "<cosign sig or empty>", "keyid": "" } ]
      },
      "integrity": {
        "integrity_level": "hashed" | "signed",
        "digest": { "sha256": "<hex over the exact decoded payload bytes>" },
        "signer_identity": null | "<disclosed signer>",
        "tool": { "name": "finlexpurple", "version": "<x.y.z>" },
        "signing": { ... full honest signing disclosure ... }
      }
    }

The in-toto Statement's ``subject`` is the finding's request/response
``evidence_hash`` and its ``predicateType`` is the versioned bundle type URI, so
a future reviewer attestation can be a *separate* statement over this bundle's
digest with zero change to this format.

**Parsing rules (v1, enforced):** consumers ignore unknown fields; minor
versions only add optional fields; unset/null/empty mean the same; any change of
meaning bumps the major (the type URI). Digests are an algorithm-agile map
(``{"sha256": ...}``) so another algorithm can be added without a schema break.
All monetary amounts / account numbers / ids ride inside the finding as strings
(never JSON numbers), so IEEE-754 drift cannot touch them.
"""

from __future__ import annotations

import base64
import hashlib
import json
from datetime import datetime, timezone
from typing import Any

from finlexpurple import __version__
from finlexpurple.detectors.schema import Finding
from finlexpurple.evidence.signing import SigningResult, hash_only

BUNDLE_SCHEMA_VERSION = 1
_HASH_PREFIX = "sha256:"

# Format discriminators. v0 is the legacy 0.3.0 shape; v1 is the current
# DSSE + in-toto Statement shape. ``verify-bundle`` accepts both forever.
BUNDLE_FORMAT_V0 = "flp-bundle/v0"
BUNDLE_FORMAT_V1 = "flp-bundle/v1"

# The major-versioned type URI for the bundle predicate (any change of meaning
# bumps this). 0.x counts as a major, so we commit to v1 now.
BUNDLE_TYPE_URI = "https://finlexpurple.com/evidence-bundle/v1"
# DSSE/in-toto constants.
IN_TOTO_STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
DSSE_PAYLOAD_TYPE = "application/vnd.in-toto+json"

# Frozen run-directory contract (Unit 1.4): the evidence bundle's filename suffix
# and documented media type, so a consumer can recognize and serve a bundle.
BUNDLE_FILENAME_SUFFIX = ".bundle.json"
BUNDLE_MEDIA_TYPE = "application/vnd.finlexpurple.evidence-bundle+json"


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


def detect_format(data: dict[str, Any]) -> str:
    """Return the bundle format (``flp-bundle/v1`` or ``flp-bundle/v0``) of a dict.

    v1 is recognised by its explicit ``bundle_format`` marker or by carrying the
    DSSE ``dsse`` + ``integrity`` envelope; everything else is treated as the
    legacy v0 shape (and validated as such by :func:`load_bundle`).
    """

    if data.get("bundle_format") == BUNDLE_FORMAT_V1 or ("dsse" in data and "integrity" in data):
        return BUNDLE_FORMAT_V1
    return BUNDLE_FORMAT_V0


def load_bundle(text: str) -> dict[str, Any]:
    """Parse bundle JSON text, raising :class:`BundleFormatError` if malformed.

    Validates the top-level shape for whichever format the bundle is in (legacy
    v0 ``payload``/``content_hash``/``signing`` or v1 ``dsse``/``integrity``) so
    verification can report a clear structural error rather than a raw
    ``KeyError`` deep inside.
    """

    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise BundleFormatError(f"bundle is not valid JSON: {exc}") from None
    if not isinstance(data, dict):
        raise BundleFormatError("bundle must be a JSON object.")

    if detect_format(data) == BUNDLE_FORMAT_V1:
        dsse = data.get("dsse")
        integrity = data.get("integrity")
        if not isinstance(dsse, dict):
            raise BundleFormatError("v1 bundle 'dsse' must be a JSON object.")
        for key in ("payloadType", "payload", "signatures"):
            if key not in dsse:
                raise BundleFormatError(f"v1 bundle 'dsse' is missing the {key!r} field.")
        if not isinstance(dsse["payload"], str):
            raise BundleFormatError("v1 bundle 'dsse.payload' must be a base64 string.")
        if not isinstance(integrity, dict):
            raise BundleFormatError("v1 bundle 'integrity' must be a JSON object.")
        if not isinstance(integrity.get("digest"), dict):
            raise BundleFormatError("v1 bundle 'integrity.digest' must be a JSON object.")
        return data

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


def bundle_content_hash(bundle: dict[str, Any]) -> str:
    """Return the ``sha256:<hex>`` integrity hash of a bundle, for either format.

    For v1 this is the digest over the exact stored payload bytes; for v0 it is
    the legacy ``content_hash`` over the canonical payload. Lets a reader (report
    markdown, CLI) quote one hash string regardless of the bundle's format.
    """

    if detect_format(bundle) == BUNDLE_FORMAT_V1:
        return f"{_HASH_PREFIX}{bundle['integrity']['digest']['sha256']}"
    return str(bundle["content_hash"])


# --- v1: DSSE + in-toto Statement -----------------------------------------


def dsse_pae(payload_type: str, payload: bytes) -> bytes:
    """DSSE Pre-Authentication Encoding of ``(payload_type, payload)``.

    ``"DSSEv1" SP len(type) SP type SP len(payload) SP payload`` (lengths as
    ASCII decimal), per the DSSE spec. This is the exact byte string a signature
    is made over, so verification reconstructs it from the stored payload bytes
    and never re-serializes the document.
    """

    type_bytes = payload_type.encode("utf-8")
    return b" ".join(
        [
            b"DSSEv1",
            str(len(type_bytes)).encode("ascii"),
            type_bytes,
            str(len(payload)).encode("ascii"),
            payload,
        ]
    )


def build_statement(
    finding: Finding,
    *,
    created_at: datetime,
    tool_version: str,
    redaction: dict[str, Any],
) -> dict[str, Any]:
    """Build the in-toto Statement v1 that becomes the DSSE payload.

    ``subject`` binds the finding's request/response ``evidence_hash`` (the
    durable thing the bundle attests to); ``predicate`` carries the finding, the
    deterministic replay log, the explicit documented hash inputs, and the
    redaction record. ``created_at`` is recorded but excluded from the subject
    digest (it is a volatile field), so two bundles of the same evidence share a
    subject even when minted at different times.
    """

    return {
        "_type": IN_TOTO_STATEMENT_TYPE,
        "subject": [
            {
                "name": finding.finding_id,
                "digest": {"sha256": _strip_prefix(finding.evidence_hash)},
            }
        ],
        "predicateType": BUNDLE_TYPE_URI,
        "predicate": {
            "bundle_format": BUNDLE_FORMAT_V1,
            "created_at": created_at.isoformat(),
            "tool": {"name": "finlexpurple", "version": tool_version},
            "finding": finding.to_dict(),
            "replay_log": finding.verification_log or "",
            "redaction": redaction,
            "hash_inputs": {
                "canonicalization": "none (the exact serialized Statement bytes "
                "are stored and signed; verification never re-serializes)",
                "signed_object": "DSSE PAE over this in-toto Statement's bytes",
                "included": [
                    (
                        "the entire in-toto Statement bytes: _type, subject "
                        "(finding_id + evidence_hash), predicateType, and the full "
                        "predicate (finding, replay_log, redaction record, tool)"
                    )
                ],
                "excluded_volatile": [
                    (
                        "nothing is excluded from the stored payload digest; "
                        "volatile values (created_at, response Date, nonces, "
                        "session cookies, CSRF tokens) are redacted at capture "
                        "(see 'redaction') and 'created_at' is kept out of the "
                        "subject digest only"
                    )
                ],
            },
        },
    }


def serialize_statement(statement: dict[str, Any]) -> bytes:
    """Serialize a Statement to the exact bytes that are stored (base64) and signed.

    Deterministic (sorted keys, no insignificant whitespace, ASCII) so golden
    vectors stay stable; but these bytes are stored verbatim, so verification
    hashes them directly and does not depend on reproducing this serialization.
    """

    return json.dumps(
        statement, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")


def build_bundle_v1(
    finding: Finding,
    *,
    signing: SigningResult | None = None,
    created_at: datetime | None = None,
    tool_version: str | None = None,
    redaction: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Assemble a v1 (DSSE + in-toto) bundle for ``finding``.

    The in-toto Statement is serialized once; those exact bytes are base64-stored
    and their sha256 recorded under ``integrity.digest``. ``signing`` is the
    disclosed outcome of a signing attempt over the DSSE PAE of those bytes; when
    omitted the bundle is honestly hash-only (``integrity_level: "hashed"``).
    """

    stamp = created_at or datetime.now(timezone.utc)
    version = tool_version or __version__
    redaction_record = redaction if redaction is not None else {"redacted": False, "fields": []}

    statement = build_statement(
        finding, created_at=stamp, tool_version=version, redaction=redaction_record
    )
    payload_bytes = serialize_statement(statement)
    payload_b64 = base64.b64encode(payload_bytes).decode("ascii")
    payload_digest = hashlib.sha256(payload_bytes).hexdigest()

    result = signing if signing is not None else hash_only()
    signature = result.signature if result.signed else None

    return {
        "bundle_format": BUNDLE_FORMAT_V1,
        "dsse": {
            "payloadType": DSSE_PAYLOAD_TYPE,
            "payload": payload_b64,
            "signatures": [{"sig": signature or "", "keyid": ""}],
        },
        "integrity": {
            "integrity_level": "signed" if result.signed else "hashed",
            "digest": {"sha256": payload_digest},
            "signer_identity": result.detail if result.signed else None,
            "tool": {"name": "finlexpurple", "version": version},
            "signing": result.to_dict(),
        },
    }


def _strip_prefix(value: str) -> str:
    """Return a bare hex digest, dropping an optional ``sha256:`` prefix."""

    return value.strip().lower().removeprefix(_HASH_PREFIX)
