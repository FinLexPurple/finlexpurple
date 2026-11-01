"""Anonymous pack download + verify-then-atomic-swap cache (Decision 2).

Fetches a signed, data-only pack from the public packs repo over **anonymous
HTTPS** (no token, no auth header), through the **default-deny egress policy**
(the packs host must be explicitly allow-listed; nothing else opens). Redirects
are followed manually and the egress policy is re-checked on **every hop**
(initial URL and each ``Location``), so a redirect to a host that is not
allow-listed — e.g. a GitHub Release asset that 302s to a CDN host — fails
closed rather than slipping past the allow-list.

The newly fetched pack is fully verified **before** it can replace the good
cache: a failed verification never swaps, and a manifest older than the installed
one is rejected unless the caller explicitly asks to roll back (recording the
reason).

The CLI holds **no credential** for the public or the private repo. The transport
and the signature-verify backend are injectable so tests exercise every path
(success, tampered, wrong identity, rollback-reject) with the real network and
cosign mocked.
"""

from __future__ import annotations

import os
import tempfile
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

import httpx

from finlexpurple.intel.pack import PackValidationError, load_pack
from finlexpurple.intel.signing import CosignVerifyBackend, ExpectedIdentity, verify_pack
from finlexpurple.security.egress_policy import EgressPolicy

# url -> raw bytes. Anonymous: the default sends no Authorization header.
Transport = Callable[[str], bytes]

_CACHE_PACK = "pack.json"
_CACHE_SIG = "pack.sig.json"
_TIMEOUT_SECONDS = 30.0
_MAX_REDIRECTS = 5


@dataclass(frozen=True)
class DownloadResult:
    """The outcome of a fetch+verify+cache attempt."""

    ok: bool
    cached_pack: Path | None
    version: str | None
    reason: str


def _default_transport(egress: EgressPolicy) -> Transport:
    """An anonymous HTTPS GET that egress-checks every hop and sends no credentials."""

    def transport(url: str) -> bytes:
        current = url
        with httpx.Client(follow_redirects=False, trust_env=False, timeout=_TIMEOUT_SECONDS) as client:
            for _ in range(_MAX_REDIRECTS + 1):
                egress.check_url(current)  # default-deny on EVERY hop, redirect targets included
                response = client.get(current)  # no auth header is ever added
                if response.is_redirect:
                    location = response.headers.get("location")
                    if not location:
                        raise httpx.HTTPError(f"redirect from {current} had no Location header")
                    current = str(response.url.join(location))
                    continue
                response.raise_for_status()
                return response.content
        raise httpx.HTTPError(f"too many redirects (>{_MAX_REDIRECTS}) fetching {url}")

    return transport


def _installed_created(cache_dir: Path) -> str | None:
    """Return the ``created`` timestamp of the currently cached pack, if any."""

    cached = cache_dir / _CACHE_PACK
    if not cached.exists():
        return None
    try:
        return load_pack(cached.read_text(encoding="utf-8")).manifest.created
    except (OSError, PackValidationError):
        return None


def fetch_and_cache(
    pack_url: str,
    signature_url: str,
    *,
    egress: EgressPolicy,
    cache_dir: Path,
    expected_identity: ExpectedIdentity | None,
    expected_sha256: str | None = None,
    transport: Transport | None = None,
    verify_backend: CosignVerifyBackend | None = None,
    allow_rollback: bool = False,
) -> DownloadResult:
    """Fetch, fully verify, and (only then) atomically swap the cached pack.

    Order matters for safety: fetch over egress-checked anonymous HTTPS, verify
    the bytes + the identity-pinned signature in a temp dir, check rollback, and
    **only** if everything passes replace the cache atomically with ``os.replace``.
    A downloaded pack always *requires* a verified identity-pinned signature; the
    cosign signature covers the exact bytes, so ``expected_sha256`` is an optional
    extra pin (when given it must match). Any failure returns ``ok=False`` and
    leaves the existing good cache untouched.
    """

    fetch = transport if transport is not None else _default_transport(egress)
    try:
        pack_bytes = fetch(pack_url)
        sig_bytes = fetch(signature_url)
    except Exception as exc:  # noqa: BLE001 - any fetch failure must leave the good cache intact
        return DownloadResult(False, None, None, f"download failed: {exc}")

    cache_dir.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="flp-intel-") as tmp:
        tmp_pack = Path(tmp) / _CACHE_PACK
        tmp_sig = Path(tmp) / _CACHE_SIG
        tmp_pack.write_bytes(pack_bytes)
        tmp_sig.write_bytes(sig_bytes)

        verify = verify_pack(
            pack_bytes, expected_sha256=expected_sha256, require_signature=True,
            signature_bundle_path=tmp_sig, blob_path=tmp_pack,
            expected_identity=expected_identity, backend=verify_backend,
        )
        if not verify.ok:
            return DownloadResult(False, None, None, f"verification failed: {verify.messages[-1]}")

        try:
            manifest = load_pack(pack_bytes.decode("utf-8")).manifest
        except (UnicodeDecodeError, PackValidationError) as exc:
            return DownloadResult(False, None, None, f"pack did not validate as data: {exc}")

        installed = _installed_created(cache_dir)
        if installed is not None and manifest.created < installed and not allow_rollback:
            return DownloadResult(
                False, None, manifest.version,
                f"rollback refused: fetched pack ({manifest.created}) is older than the "
                f"installed one ({installed}); pass allow_rollback to override.",
            )

        # Verified and not a rollback: swap atomically (pack then signature).
        os.replace(tmp_pack, cache_dir / _CACHE_PACK)
        os.replace(tmp_sig, cache_dir / _CACHE_SIG)

    reason = "verified and cached" + (" (explicit rollback)" if allow_rollback and installed else "")
    return DownloadResult(True, cache_dir / _CACHE_PACK, manifest.version, reason)
