"""Pack signature verification — identity-pinned, fail-closed (Decision 2).

Mirrors the project's existing signing style (``evidence/signing.py`` /
``evidence/verify.py``): the canonical **content hash is checked offline** and
the Sigstore signature is the **online** trust anchor, verified by wrapping the
real ``cosign verify-blob`` binary through ``TOOL_REGISTRY`` — no Python
``sigstore`` library is used (none is installed), and no signature is ever
fabricated.

Two things make this stricter than a generic "valid Sigstore signature" check:

* **Expected-identity pinning.** Keyless verification passes either
  ``--certificate-identity`` (an exact signer) or ``--certificate-identity-regexp``
  (the published packs channel: the one publishing workflow of the packs repo,
  with the release *tag* allowed to vary) plus ``--certificate-oidc-issuer``, so
  cosign only accepts a signature from that pinned identity. Any other valid
  Sigstore signature is rejected.
* **Fail-closed.** When a run *requires* a signature but no pinned identity is
  configured, or no signature bundle is present, verification does **not** pass —
  it reports honestly and ``ok`` is False. A downloaded pack is never trusted on
  its hash alone; only the shipped baseline pack (:mod:`finlexpurple.intel`) is
  verified hash-only, and it is labeled as such.

On the signed channel the cosign signature is computed over the **exact pack
bytes**, so it is the integrity *and* authenticity guarantee. A pinned
``expected_sha256`` is therefore **optional** on that path — defence-in-depth to
nail a specific known release — and when absent the signature stands alone. An
**unsigned** pack (the baseline) still *must* be hash-pinned, or it is refused:
unsigned-and-unpinned is trusted by nothing.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from finlexpurple.tools.registry import TOOL_REGISTRY

# The GitHub Actions OIDC issuer, as documented in `cosign verify-blob --help`
# (not a guess). The expected certificate-identity (the workflow path/ref, exact
# or regexp) is a deployment value supplied by the caller, never hardcoded here.
GITHUB_ACTIONS_OIDC_ISSUER = "https://token.actions.githubusercontent.com"

_COSIGN_TIMEOUT_SECONDS = 120.0

# (identity_matcher, issuer, signature_bundle_path, blob_path) -> cosign (returncode, stdout, stderr).
# ``identity_matcher`` is the exact identity or the identity regexp (see ExpectedIdentity.matcher);
# which cosign flag carries it is decided by the default backend from the pinned identity.
CosignVerifyBackend = Callable[[str, str, str, str], tuple[int, str, str]]


@dataclass(frozen=True)
class ExpectedIdentity:
    """The pinned keyless signer: either an exact identity or an identity regexp, + OIDC issuer.

    Exactly one of ``identity`` (exact match) or ``identity_regexp`` (anchored
    regular expression, for the published channel where the release tag varies)
    must be set. ``issuer`` defaults to the documented GitHub Actions issuer.
    """

    identity: str | None = None
    identity_regexp: str | None = None
    issuer: str = GITHUB_ACTIONS_OIDC_ISSUER

    def __post_init__(self) -> None:
        if bool(self.identity) == bool(self.identity_regexp):
            raise ValueError(
                "ExpectedIdentity requires exactly one of identity (exact) or "
                "identity_regexp (pattern)."
            )

    @property
    def matcher(self) -> str:
        """The identity string to pin against (exact value or regexp pattern)."""

        return self.identity if self.identity is not None else str(self.identity_regexp)

    @property
    def cosign_flag(self) -> str:
        """The cosign flag that carries :attr:`matcher` (exact vs. regexp)."""

        return "--certificate-identity" if self.identity is not None else "--certificate-identity-regexp"


@dataclass(frozen=True)
class PackVerifyResult:
    """The disclosed outcome of verifying a pack's bytes (and optionally its signature)."""

    ok: bool
    hash_ok: bool
    recomputed_sha256: str
    expected_sha256: str | None
    signature_checked: bool
    signature_ok: bool | None
    pinned_identity: str | None
    messages: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "hash_ok": self.hash_ok,
            "recomputed_sha256": self.recomputed_sha256,
            "expected_sha256": self.expected_sha256,
            "signature_checked": self.signature_checked,
            "signature_ok": self.signature_ok,
            "pinned_identity": self.pinned_identity,
            "messages": list(self.messages),
        }


def _sha256(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _cosign_verify_argv(expected_identity: ExpectedIdentity, bundle_path: str, blob_path: str) -> list[str]:
    """Build the ``cosign verify-blob`` argv with the right identity flag (exact vs. regexp)."""

    return [
        "verify-blob",
        "--bundle", bundle_path,
        expected_identity.cosign_flag, expected_identity.matcher,
        "--certificate-oidc-issuer", expected_identity.issuer,
        blob_path,
    ]


def _default_cosign_verify_backend(expected_identity: ExpectedIdentity) -> CosignVerifyBackend:
    """Wrap the real ``cosign verify-blob`` (via TOOL_REGISTRY) as a verify backend."""

    cosign = TOOL_REGISTRY["cosign"]

    def backend(identity: str, issuer: str, bundle_path: str, blob_path: str) -> tuple[int, str, str]:
        argv: Sequence[str] = _cosign_verify_argv(expected_identity, bundle_path, blob_path)
        result = cosign.run(argv, timeout=_COSIGN_TIMEOUT_SECONDS)
        return (result.returncode if result.returncode is not None else -1, result.stdout, result.stderr)

    return backend


def verify_pack(
    pack_bytes: bytes,
    *,
    expected_sha256: str | None,
    require_signature: bool,
    signature_bundle_path: Path | None = None,
    blob_path: Path | None = None,
    expected_identity: ExpectedIdentity | None = None,
    backend: CosignVerifyBackend | None = None,
) -> PackVerifyResult:
    """Verify a pack's bytes and, when required, its identity-pinned signature.

    ``expected_sha256`` pins the exact bytes; it is **optional on the signed
    path** (the cosign signature already covers the bytes) and, when given, must
    match. When ``require_signature`` is True the result only passes if a
    signature bundle is present, a pinned ``expected_identity`` is configured, and
    ``cosign verify-blob`` accepts the signature for exactly that identity —
    otherwise it **fails closed** (``ok`` False), never trusting the hash alone.
    When ``require_signature`` is False (the shipped baseline) the pack **must**
    be hash-pinned or it is refused; a matching pinned hash is the guarantee and
    the result is honestly labeled "hash-only, unsigned".
    """

    recomputed = _sha256(pack_bytes)
    messages: list[str] = []
    if expected_sha256 is None:
        hash_pinned = False
        hash_ok = True  # not pinned here; on the signed path the signature covers these exact bytes
        messages.append(f"content hash not pinned; recomputed {recomputed} (the signature covers these bytes).")
    else:
        hash_pinned = True
        hash_ok = recomputed == expected_sha256
        messages.append(
            f"content hash matches ({recomputed})." if hash_ok
            else f"HASH MISMATCH: expected {expected_sha256}, recomputed {recomputed}."
        )

    signature_checked = False
    signature_ok: bool | None = None
    pinned_identity = expected_identity.matcher if expected_identity is not None else None

    if not require_signature:
        # Offline/baseline trust: an unsigned pack MUST be hash-pinned, else trust nothing.
        if not hash_pinned:
            messages.append("REFUSING TO TRUST: unsigned verification requires a pinned content hash.")
            return PackVerifyResult(
                ok=False, hash_ok=False, recomputed_sha256=recomputed, expected_sha256=expected_sha256,
                signature_checked=False, signature_ok=None, pinned_identity=pinned_identity, messages=messages,
            )
        messages.append("hash-only, unsigned verification (baseline/offline): the pinned content hash is the guarantee.")
        return PackVerifyResult(
            ok=hash_ok, hash_ok=hash_ok, recomputed_sha256=recomputed, expected_sha256=expected_sha256,
            signature_checked=False, signature_ok=None, pinned_identity=pinned_identity, messages=messages,
        )

    # A signature is required: fail closed on any missing precondition.
    if expected_identity is None:
        messages.append("REFUSING TO TRUST: a signature is required but no pinned identity is configured.")
        return PackVerifyResult(
            ok=False, hash_ok=hash_ok, recomputed_sha256=recomputed, expected_sha256=expected_sha256,
            signature_checked=False, signature_ok=None, pinned_identity=None, messages=messages,
        )
    if signature_bundle_path is None or blob_path is None:
        messages.append("REFUSING TO TRUST: a signature is required but no signature bundle/blob was provided.")
        return PackVerifyResult(
            ok=False, hash_ok=hash_ok, recomputed_sha256=recomputed, expected_sha256=expected_sha256,
            signature_checked=False, signature_ok=None, pinned_identity=pinned_identity, messages=messages,
        )

    run_backend = backend if backend is not None else _default_cosign_verify_backend(expected_identity)
    try:
        returncode, stdout, stderr = run_backend(
            expected_identity.matcher, expected_identity.issuer,
            str(signature_bundle_path), str(blob_path),
        )
    except (FileNotFoundError, OSError, ValueError) as exc:
        messages.append(f"REFUSING TO TRUST: signature verification could not run ({exc}).")
        return PackVerifyResult(
            ok=False, hash_ok=hash_ok, recomputed_sha256=recomputed, expected_sha256=expected_sha256,
            signature_checked=False, signature_ok=None, pinned_identity=pinned_identity, messages=messages,
        )

    signature_checked = True
    signature_ok = returncode == 0
    if signature_ok:
        messages.append(f"signature verified by cosign for pinned identity {expected_identity.matcher!r}.")
    else:
        detail = stderr.strip() or stdout.strip() or f"cosign exited {returncode}"
        messages.append(f"SIGNATURE VERIFICATION FAILED (identity {expected_identity.matcher!r}): {detail}.")

    # Fail closed: a required signature must both exist and verify; a pinned hash (if any) must match.
    ok = hash_ok and signature_ok is True
    return PackVerifyResult(
        ok=ok, hash_ok=hash_ok, recomputed_sha256=recomputed, expected_sha256=expected_sha256,
        signature_checked=signature_checked, signature_ok=signature_ok,
        pinned_identity=pinned_identity, messages=messages,
    )
