"""Baked channel + pin defaults for intelligence-pack pull (Decision 2 Step 2).

Secure out of the box: the published packs channel URLs, the OIDC issuer, and the
pinned publishing-workflow identity (a **regexp** — the release tag varies, the
repo + workflow file do not) are baked in as DEFAULT constants, so ``pull``
verifies against the right signer with no configuration. The baked identity
regexp is kept in lock-step with ``.github/workflows/intel-pack.yml`` (a test
asserts they match, so the pin cannot silently drift from the publisher).

Each value is overridable by an env var for self-hosting/testing, and **clearing**
an override (setting it to an empty string) **fails closed** — it refuses rather
than silently falling back to the baked default or trusting an unsigned pack.

``INTEL_EXPECTED_SHA256`` is an *optional* extra pin (the cosign signature already
covers the exact bytes), so clearing it simply drops the extra pin. Downloaded
release assets 302-redirect to a CDN host; that host must be allow-listed via
``INTEL_PACKS_EGRESS_HOSTS`` (default: none) or the redirect fails closed.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from urllib.parse import urlsplit

from finlexpurple.intel.signing import GITHUB_ACTIONS_OIDC_ISSUER, ExpectedIdentity

# --- Baked defaults: the FinLexPurple published channel (matches intel-pack.yml) ---
DEFAULT_PACKS_URL = (
    "https://github.com/FinLexPurple/finlexpurple-intelligence-packs/releases/latest/download/pack.json"
)
DEFAULT_SIG_URL = (
    "https://github.com/FinLexPurple/finlexpurple-intelligence-packs/releases/latest/download/pack.sig.json"
)
# Pin: exact repo + exact workflow file + tag-refs only; the tag version varies (regexp), by design.
DEFAULT_PINNED_IDENTITY_REGEXP = (
    r"^https://github\.com/FinLexPurple/finlexpurple-intelligence-packs/"
    r"\.github/workflows/intel-pack\.yml@refs/tags/"
)
DEFAULT_OIDC_ISSUER = GITHUB_ACTIONS_OIDC_ISSUER

# Env override keys (documented for self-hosting/testing).
ENV_URL = "INTEL_PACKS_PULL_URL"
ENV_SIG_URL = "INTEL_PACKS_SIG_URL"
ENV_IDENTITY = "INTEL_PINNED_IDENTITY"  # a non-empty value pins an EXACT identity (vs the baked regexp)
ENV_SHA = "INTEL_EXPECTED_SHA256"  # optional extra pin; unset/empty => the signature stands alone
ENV_EGRESS_HOSTS = "INTEL_PACKS_EGRESS_HOSTS"  # extra allow-listed hosts (e.g. the release CDN), comma-separated


class ConfigError(RuntimeError):
    """A required pull override was cleared (set empty): refuse rather than weaken the pin."""


@dataclass(frozen=True)
class PullChannel:
    """A fully resolved, ready-to-use pull configuration."""

    pack_url: str
    signature_url: str
    expected_identity: ExpectedIdentity
    expected_sha256: str | None
    egress_hosts: tuple[str, ...]


def _resolve(env: Mapping[str, str], key: str, default: str) -> str:
    """Override if set non-empty, baked default if unset, fail closed if set-but-empty (cleared)."""

    if key not in env:
        return default
    value = env[key].strip()
    if not value:
        raise ConfigError(
            f"{key} is set but empty; refusing to fall back to the default (fail-closed). "
            f"Unset it entirely to use the baked default."
        )
    return value


def resolve_pull_channel(env: Mapping[str, str] | None = None) -> PullChannel:
    """Resolve the pull channel from baked defaults + env overrides (fail-closed on a cleared override)."""

    env = env if env is not None else os.environ
    pack_url = _resolve(env, ENV_URL, DEFAULT_PACKS_URL)
    signature_url = _resolve(env, ENV_SIG_URL, DEFAULT_SIG_URL)

    # Identity: a non-empty override pins an EXACT identity; otherwise the baked regexp.
    if ENV_IDENTITY in env:
        exact = env[ENV_IDENTITY].strip()
        if not exact:
            raise ConfigError(
                f"{ENV_IDENTITY} is set but empty; refusing to drop the identity pin (fail-closed)."
            )
        expected_identity = ExpectedIdentity(identity=exact, issuer=DEFAULT_OIDC_ISSUER)
    else:
        expected_identity = ExpectedIdentity(
            identity_regexp=DEFAULT_PINNED_IDENTITY_REGEXP, issuer=DEFAULT_OIDC_ISSUER
        )

    # Optional extra sha pin (defence-in-depth); unset/empty => the signature alone is the anchor.
    expected_sha256 = (env.get(ENV_SHA) or "").strip() or None

    # Allow-list = the channel hosts, plus any explicitly authorized redirect-target (CDN) hosts.
    hosts = {urlsplit(pack_url).hostname or "", urlsplit(signature_url).hostname or ""}
    for host in (env.get(ENV_EGRESS_HOSTS) or "").split(","):
        cleaned = host.strip()
        if cleaned:
            hosts.add(cleaned)
    hosts.discard("")
    return PullChannel(pack_url, signature_url, expected_identity, expected_sha256, tuple(sorted(hosts)))
