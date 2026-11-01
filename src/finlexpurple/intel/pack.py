"""Data-only knowledge-pack model + loader (Decision 2).

A pack is a **manifest** plus **pattern records**, all parsed and schema-validated
as data — never executed as code. Two integrity properties are enforced by the
loader, not left to callers:

* **Permutation-only / registry rule.** Every name a pattern lists must already
  exist in :mod:`finlexpurple.agents.registry`. A record that names an agent/check
  the live registry does not have is rejected — a pack can only ever *reorder*
  known checks, exactly like the planner/selector boundary. (Whether a verified
  pack is then *allowed* to influence a run is enforced again, separately, in
  :mod:`finlexpurple.intel.apply`.)
* **Per-record content hash.** Each record carries a ``content_hash`` over its own
  canonical data; the loader recomputes and rejects a mismatch, so a record
  altered inside an otherwise well-formed pack is caught even before any
  signature check.

Models use pydantic v2 with ``extra="forbid"`` so an unexpected key (an attempt
to smuggle a field the code does not read) fails validation rather than being
silently ignored. The canonical JSON form is reused from
:mod:`finlexpurple.evidence.bundle` so hashing matches the rest of the product.
"""

from __future__ import annotations

import hashlib

from pydantic import BaseModel, ConfigDict, ValidationError

from finlexpurple.agents.registry import get_agent
from finlexpurple.evidence.bundle import canonical_json

# The pack schema this client understands. A pack declaring a newer schema is
# rejected rather than half-read (the loader fails closed).
SUPPORTED_SCHEMA_VERSION = 1

# Provenance values a record may carry. Lab data (targets we control) is
# higher-trust; community data is advisory-only and quarantined until a
# maintainer reviews it (never trusted by submitter count).
_PROVENANCE = frozenset({"lab", "community"})


class PackValidationError(ValueError):
    """A pack is not a well-formed, schema-valid, registry-consistent data pack."""


class PackFileRef(BaseModel):
    """One file covered by the manifest: its path, sha256, and size in bytes."""

    model_config = ConfigDict(extra="forbid")
    path: str
    sha256: str
    size: int


class Manifest(BaseModel):
    """Pack manifest: versioning, covered files, and the signature reference.

    ``signature_ref`` points at the detached signature/cert material the verifier
    checks (Sigstore keyless); it is a reference only — this model never verifies
    anything, and the manifest is data like everything else here.
    """

    model_config = ConfigDict(extra="forbid")
    version: str
    schema_version: int
    min_client_version: str
    created: str
    files: list[PackFileRef] = []
    previous_version: str | None = None
    signature_ref: str | None = None


class PatternRecord(BaseModel):
    """One data-only learned pattern.

    ``ordered_agents`` is a run-order hint over **already-registered** check/agent
    names; ``reproduced_strategy`` records which strategy reproduced the issue (for
    a human to read); ``provenance`` is "lab" or "community"; ``content_hash`` is a
    self-hash the loader re-checks. There is no field that carries code, a payload,
    or a target — a record only ever *reorders known checks*.
    """

    model_config = ConfigDict(extra="forbid")
    fingerprint: str
    ordered_agents: list[str]
    reproduced_strategy: str
    provenance: str
    content_hash: str

    def recompute_hash(self) -> str:
        """The sha256 over this record's canonical data fields (excludes the hash itself)."""

        canonical = canonical_json({
            "fingerprint": self.fingerprint,
            "ordered_agents": self.ordered_agents,
            "reproduced_strategy": self.reproduced_strategy,
            "provenance": self.provenance,
        })
        return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


class Pack(BaseModel):
    """A complete data-only pack: its manifest and its pattern records."""

    model_config = ConfigDict(extra="forbid")
    manifest: Manifest
    patterns: list[PatternRecord] = []


def record_content_hash(
    *, fingerprint: str, ordered_agents: list[str], reproduced_strategy: str, provenance: str
) -> str:
    """Compute the canonical ``content_hash`` for a record's data fields.

    The one helper a builder and the loader share, so a record written by the
    pack builder hashes identically to how the loader re-checks it.
    """

    canonical = canonical_json({
        "fingerprint": fingerprint,
        "ordered_agents": ordered_agents,
        "reproduced_strategy": reproduced_strategy,
        "provenance": provenance,
    })
    return "sha256:" + hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def load_pack(text: str) -> Pack:
    """Parse + validate pack JSON as data, enforcing schema, hashes, and the registry rule.

    Raises :class:`PackValidationError` for malformed JSON, a schema mismatch
    (``extra="forbid"`` or an unsupported ``schema_version``), a record whose
    recomputed ``content_hash`` differs, an unknown ``provenance``, or any
    ``ordered_agents`` name the live registry does not have. The pack is only ever
    parsed — never executed.
    """

    try:
        pack = Pack.model_validate_json(text)
    except ValidationError as exc:
        raise PackValidationError(f"pack is not a well-formed data pack: {exc}") from None

    if pack.manifest.schema_version != SUPPORTED_SCHEMA_VERSION:
        raise PackValidationError(
            f"unsupported pack schema_version {pack.manifest.schema_version} "
            f"(this client supports {SUPPORTED_SCHEMA_VERSION}); refusing to read it."
        )

    for index, record in enumerate(pack.patterns):
        if record.provenance not in _PROVENANCE:
            raise PackValidationError(
                f"pattern {index}: unknown provenance {record.provenance!r} (expected one of {sorted(_PROVENANCE)})."
            )
        if record.recompute_hash() != record.content_hash:
            raise PackValidationError(
                f"pattern {index}: content_hash mismatch — the record was altered after it was written."
            )
        for name in record.ordered_agents:
            if get_agent(name) is None:
                raise PackValidationError(
                    f"pattern {index}: {name!r} is not a registered agent/check; a pack may only "
                    "reorder names that already exist in the registry (never add one)."
                )
    return pack
