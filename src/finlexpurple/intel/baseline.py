"""The shipped first-party baseline pack (Decision 2).

A small, data-only pack bundled inside the wheel (``baseline/pack.json``) so the
tool has working intelligence **fully air-gapped, with no download**. The baseline
is **lab provenance** (ground truth from targets we control) and is verified
**hash-only against a pinned sha256** — honestly labeled "unsigned", never
presented as a full signature check (keyless verification needs connectivity).
The pinned hash catches a corrupted or swapped shipped file.
"""

from __future__ import annotations

from importlib.resources import files

from finlexpurple.intel.pack import Pack, PackValidationError, load_pack
from finlexpurple.intel.signing import PackVerifyResult, verify_pack

# The sha256 of the shipped baseline/pack.json, pinned so a corrupted or swapped
# file fails verification rather than loading silently. Regenerate this if the
# shipped baseline is ever updated (and only then).
BASELINE_SHA256 = "sha256:a6b0632f907f485b4e5916b559bd56409c7c78c6acb878f2f1e7d918b5c0c60d"


class BaselineError(RuntimeError):
    """The shipped baseline pack is missing, corrupted, or not a valid data pack."""


def _baseline_bytes() -> bytes:
    """Read the baseline pack bundled in the wheel."""

    return (files("finlexpurple.intel") / "baseline" / "pack.json").read_bytes()


def verify_baseline() -> PackVerifyResult:
    """Hash-only verify the shipped baseline against its pinned sha256 (unsigned, offline)."""

    return verify_pack(_baseline_bytes(), expected_sha256=BASELINE_SHA256, require_signature=False)


def load_baseline() -> Pack:
    """Return the shipped baseline pack, or raise if it fails its pinned hash / validation.

    The baseline must both match ``BASELINE_SHA256`` (integrity of the shipped
    file) and parse as a valid, registry-consistent data pack; either failure is
    a :class:`BaselineError` rather than a silently-loaded pack.
    """

    result = verify_baseline()
    if not result.ok:
        raise BaselineError(f"shipped baseline failed hash-only verification: {result.messages[-1]}")
    try:
        return load_pack(_baseline_bytes().decode("utf-8"))
    except (UnicodeDecodeError, PackValidationError) as exc:
        raise BaselineError(f"shipped baseline is not a valid data pack: {exc}") from None
