"""Pack signature verification — identity-pinned, fail-closed (Decision 2).

Mirrors the project's existing signing style (``evidence/signing.py`` /
``evidence/verify.py``): the canonical **content hash is always checked and works
offline**; the Sigstore signature is the **online** trust anchor, verified by
wrapping the real ``cosign verify-blob`` binary through ``TOOL_REGISTRY`` — no
Python ``sigstore`` library is used (none is installed), and no signature is ever
fabricated.

Two things make this stricter than a generic "valid Sigstore signature" check:

* **Expected-identity pinning.** Keyless verification passes
  ``--certificate-identity`` + ``--certificate-oidc-issuer`` so cosign only
  accepts a signature from the **one** publishing-workflow OIDC identity of the
  packs repo. Any other valid Sigstore signature is rejected.
* **Fail-closed.** When a run *requires* a signature but no pinned identity is
  configured, or no signature bundle is present, verification does **not** pass —
  it reports hash-only, "unsigned", honestly, and ``ok`` is False. A downloaded
  pack is never trusted on its hash alone; only the shipped baseline pack
  (:mod:`finlexpurple.intel`) is verified hash-only, and it is labeled as such.

The exact ``certificate-identity`` string is a deployment value (it depends on
the publishing workflow's path/ref) and is **injected**, never guessed here.
"""

from __future__ import annotations

import hashlib
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from finlexpurple.tools.registry import TOOL_REGISTRY

# The GitHub Actions OIDC issuer, as documented in `cosign verify-blob --help`
# (not a guess). The expected certificate-identity (the workflow path/ref) is a
# deployment value supplied by the caller, never hardcoded here.
GITHUB_ACTIONS_OIDC_ISSUER = "https://token.actions.githubusercontent.com"

_COSIGN_TIMEOUT_SECONDS = 120.0

# (identity, issuer, signature_bundle_path, blob_path) -> cosign (returncode, stdout, stderr).
CosignVerifyBackend = Callable[[str, str, str, str], tuple[int, str, str]]


@dataclass(frozen=True)
class ExpectedIdentity:
    """The pinned keyless signer: the publishing workflow's identity + OIDC issuer."""

    identity: str
    issuer: str = GITHUB_ACTIONS_OIDC_ISSUER


@dataclass(frozen=True)
class PackVerifyResult:
    """The disclosed outcome of verifying a pack's bytes (and optionally its signature)."""

    ok: bool
    hash_ok: bool
    recomputed_sha256: str
    expected_sha256: str
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


def _default_cosign_verify_backend() -> CosignVerifyBackend:
    """Wrap the real ``cosign verify-blob`` (via TOOL_REGISTRY) as a verify backend."""

    cosign = TOOL_REGISTRY["cosign"]

    def backend(identity: str, issuer: str, bundle_path: str, blob_path: str) -> tuple[int, str, str]:
        argv: Sequence[str] = [
            "verify-blob",
            "--bundle", bundle_path,
            "--certificate-identity", identity,
            "--certificate-oidc-issuer", issuer,
            blob_path,
        ]
        result = cosign.run(argv, timeout=_COSIGN_TIMEOUT_SECONDS)
        return (result.returncode if result.returncode is not None else -1, result.stdout, result.stderr)

    return backend


def verify_pack(
    pack_bytes: bytes,
    *,
    expected_sha256: str,
    require_signature: bool,
    signature_bundle_path: Path | None = None,
    blob_path: Path | None = None,
    expected_identity: ExpectedIdentity | None = None,
    backend: CosignVerifyBackend | None = None,
) -> PackVerifyResult:
    """Verify a pack's bytes against ``expected_sha256`` and, when required, its signature.

    The hash check is always performed and is fully offline. When
    ``require_signature`` is True the result only passes if a signature bundle is
    present, a pinned ``expected_identity`` is configured, and ``cosign
    verify-blob`` accepts the signature for exactly that identity — otherwise it
    **fails closed** (``ok`` False), never trusting the hash alone. When
    ``require_signature`` is False (the shipped baseline pack) the hash is the
    guarantee and the result is honestly labeled "hash-only, unsigned".
    """

    recomputed = _sha256(pack_bytes)
    hash_ok = recomputed == expected_sha256
    messages: list[str] = []
    messages.append(
        f"content hash matches ({recomputed})." if hash_ok
        else f"HASH MISMATCH: expected {expected_sha256}, recomputed {recomputed}."
    )

    signature_checked = False
    signature_ok: bool | None = None
    pinned_identity = expected_identity.identity if expected_identity is not None else None

    if not require_signature:
        messages.append("hash-only, unsigned verification (baseline/offline): the content hash is the guarantee.")
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

    run_backend = backend if backend is not None else _default_cosign_verify_backend()
    try:
        returncode, stdout, stderr = run_backend(
            expected_identity.identity, expected_identity.issuer,
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
        messages.append(f"signature verified by cosign for pinned identity {expected_identity.identity!r}.")
    else:
        detail = stderr.strip() or stdout.strip() or f"cosign exited {returncode}"
        messages.append(f"SIGNATURE VERIFICATION FAILED (identity {expected_identity.identity!r}): {detail}.")

    # Fail closed: a required signature must both exist and verify; the hash must also match.
    ok = hash_ok and signature_ok is True
    return PackVerifyResult(
        ok=ok, hash_ok=hash_ok, recomputed_sha256=recomputed, expected_sha256=expected_sha256,
        signature_checked=signature_checked, signature_ok=signature_ok,
        pinned_identity=pinned_identity, messages=messages,
    )
