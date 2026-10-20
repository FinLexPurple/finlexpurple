"""Best-effort bundle signing that wraps Sigstore/cosign (Phase 12; §23, §20).

The content hash (bundle.py) is always produced; a *signature* is best-effort
and its presence or absence is always disclosed. Three modes (decisions.md §23):

* **sigstore-keyless** — default when online; keyless OIDC signing via cosign.
* **hash-only** — default when air-gapped; no signature, stated plainly.
* **offline-managed-key** — opt-in; cosign signs with a user-managed key.

Signing is **wrapped, not reimplemented** (§20): we shell out to ``cosign``
through the hardened sandbox and parse its real output; we never fabricate a
signature. Crucially, nothing silently degrades — if keyless/managed signing is
requested but cosign is missing or fails, the result is an **honest hash-only
record** that says exactly why, with ``signed=False``. The signing backend is
injectable so the real binary is wrapped in deployment while tests drive the
success and failure paths deterministically.
"""

from __future__ import annotations

import tempfile
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Any

from finlexpurple.tools.registry import TOOL_REGISTRY

# Signs the given content hash; returns (returncode, stdout, stderr) from cosign.
SigningBackend = Callable[[str], tuple[int, str, str]]

_COSIGN_TIMEOUT_SECONDS = 120.0


class SigningMode(str, Enum):
    """How a bundle was (or was not) signed."""

    SIGSTORE_KEYLESS = "sigstore-keyless"
    HASH_ONLY = "hash-only"
    OFFLINE_MANAGED_KEY = "offline-managed-key"


@dataclass(frozen=True)
class SigningResult:
    """The disclosed outcome of a signing attempt.

    ``requested_mode`` is what the run asked for; ``effective_mode`` is what was
    actually achieved (they differ when a requested signature could not be
    produced and the bundle fell back to hash-only — always with ``signed`` False
    and a ``detail`` saying why). ``signature`` is cosign's real output verbatim,
    or ``None``.
    """

    requested_mode: SigningMode
    effective_mode: SigningMode
    signed: bool
    signature: str | None
    detail: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "requested_mode": self.requested_mode.value,
            "effective_mode": self.effective_mode.value,
            "signed": self.signed,
            "signature": self.signature,
            "detail": self.detail,
        }


def hash_only(detail: str | None = None) -> SigningResult:
    """A hash-only result: no signature, the content hash is the sole guarantee."""

    return SigningResult(
        requested_mode=SigningMode.HASH_ONLY,
        effective_mode=SigningMode.HASH_ONLY,
        signed=False,
        signature=None,
        detail=detail
        or "hash-only: no signature was requested; the canonical content hash is the integrity guarantee.",
    )


def _degraded(requested_mode: SigningMode, detail: str) -> SigningResult:
    """A honest fallback: a signature was *requested* but could not be produced.

    ``requested_mode`` is preserved so the disclosure says what was attempted,
    while ``effective_mode`` is hash-only — nothing was signed.
    """

    return SigningResult(
        requested_mode=requested_mode,
        effective_mode=SigningMode.HASH_ONLY,
        signed=False,
        signature=None,
        detail=detail,
    )


def determine_mode(*, online: bool, managed_key: Path | None = None) -> SigningMode:
    """Pick the signing mode from connectivity and configuration (decisions.md §23).

    A configured offline managed key wins (explicit opt-in); otherwise online
    runs sign keyless and air-gapped runs are hash-only.
    """

    if managed_key is not None:
        return SigningMode.OFFLINE_MANAGED_KEY
    return SigningMode.SIGSTORE_KEYLESS if online else SigningMode.HASH_ONLY


def _default_cosign_backend(mode: SigningMode, managed_key: Path | None) -> SigningBackend:
    """Wrap the real ``cosign`` binary (via the hardened sandbox) as a backend.

    Writes the content hash to a temp file and runs ``cosign sign-blob`` over it,
    keyless or with ``--key`` for the managed-key mode. Raises
    ``FileNotFoundError`` if cosign is not installed, which :func:`sign` turns
    into an honest hash-only result.
    """

    cosign = TOOL_REGISTRY["cosign"]

    def backend(content_hash: str) -> tuple[int, str, str]:
        with tempfile.TemporaryDirectory(prefix="flp-cosign-") as tmp:
            blob = Path(tmp) / "content-hash.txt"
            blob.write_text(content_hash, encoding="utf-8")
            argv: Sequence[str] = ["sign-blob", "--yes", str(blob)]
            if mode is SigningMode.OFFLINE_MANAGED_KEY:
                if managed_key is None:
                    raise ValueError("offline-managed-key mode requires a key path.")
                argv = ["sign-blob", "--key", str(managed_key), "--yes", str(blob)]
            result = cosign.run(argv, timeout=_COSIGN_TIMEOUT_SECONDS, cwd=Path(tmp))
            return (result.returncode if result.returncode is not None else -1, result.stdout, result.stderr)

    return backend


def sign(
    content_hash: str,
    *,
    mode: SigningMode,
    backend: SigningBackend | None = None,
    managed_key: Path | None = None,
) -> SigningResult:
    """Sign ``content_hash`` per ``mode``, degrading to an honest hash-only record.

    Hash-only mode returns immediately with no signature. For keyless/managed
    mode the signing ``backend`` is used (the real cosign wrapper by default);
    if cosign is absent, errors, or returns non-zero, the result is hash-only
    with ``signed=False`` and a ``detail`` explaining why — never a fabricated or
    silently-dropped signature.
    """

    if mode is SigningMode.HASH_ONLY:
        return hash_only()

    try:
        run_backend = backend if backend is not None else _default_cosign_backend(mode, managed_key)
        returncode, stdout, stderr = run_backend(content_hash)
    except FileNotFoundError:
        return _degraded(
            mode,
            f"{mode.value} signing was requested but cosign is not installed; "
            "produced a hash-only bundle (nothing was signed).",
        )
    except (OSError, ValueError) as exc:
        return _degraded(
            mode, f"{mode.value} signing could not run ({exc}); produced a hash-only bundle."
        )

    if returncode != 0:
        reason = stderr.strip() or stdout.strip() or f"cosign exited {returncode}"
        return _degraded(
            mode,
            f"{mode.value} signing failed ({reason}); produced a hash-only bundle (nothing was signed).",
        )

    signature = stdout.strip()
    if not signature:
        return _degraded(
            mode, f"{mode.value} signing returned no signature; produced a hash-only bundle."
        )
    return SigningResult(
        requested_mode=mode,
        effective_mode=mode,
        signed=True,
        signature=signature,
        detail=f"signed with cosign ({mode.value}); signature is over the canonical content hash.",
    )
