"""Default-deny network egress policy (Phase 7; decisions.md §15).

This is the single allow-list that every outbound destination is checked
against. By default a running scan may reach only two kinds of host: the
confirmed in-scope target (Phase 4 scope) and the configured LLM provider
(Phase 3). Everything else is **blocked and logged** unless the user explicitly
allow-lists it. This phase builds and exposes the enforcement point; Phase 20
performs the cross-cutting audit that every outbound call in the codebase
routes through it.

The policy is host-level and conservative on purpose: "not explicitly allowed"
always means blocked, never a best-guess allow.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from urllib.parse import urlsplit

logger = logging.getLogger(__name__)

# Default API hostnames for the cloud providers, used to allow-list the one the
# user configured. These are the documented default endpoints; a user on a
# non-default/regional endpoint adds it via ALLOWED_EGRESS_HOSTS.
_CLOUD_PROVIDER_HOSTS: dict[str, str] = {
    "anthropic": "api.anthropic.com",
    "openai": "api.openai.com",
    "openrouter": "openrouter.ai",
    "gemini": "generativelanguage.googleapis.com",
}


class EgressBlockedError(PermissionError):
    """An outbound destination was blocked by the default-deny egress policy."""


def _normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")


class EgressPolicy:
    """An explicit allow-list of reachable hosts; everything else is denied.

    Construct via :meth:`for_run` so the target host(s), the configured provider
    host, and any user-allow-listed hosts are combined in one place. ``check_*``
    raises :class:`EgressBlockedError` (after logging) for anything not on the
    list — an empty or malformed destination is treated as blocked, not allowed.
    """

    def __init__(self, allowed_hosts: Iterable[str]) -> None:
        self._allowed = frozenset(
            _normalize_host(h) for h in allowed_hosts if h and h.strip()
        )

    @property
    def allowed_hosts(self) -> frozenset[str]:
        return self._allowed

    def is_allowed_host(self, host: str | None) -> bool:
        return bool(host) and _normalize_host(host or "") in self._allowed

    def check_host(self, host: str | None) -> None:
        """Raise (and log) unless ``host`` is explicitly allowed."""

        if not self.is_allowed_host(host):
            # Log the host so a blocked attempt is auditable, but never echo
            # anything beyond the host (no query/credentials).
            logger.warning(
                "Blocked out-of-scope egress to host %r (default-deny egress policy)",
                _normalize_host(host or ""),
            )
            raise EgressBlockedError(
                "Egress blocked: destination is not in the confirmed target, the "
                "configured provider, or the egress allow-list."
            )

    def check_url(self, url: str) -> None:
        """Raise (and log) unless the URL's host is explicitly allowed."""

        try:
            host = urlsplit(url).hostname
        except ValueError:
            host = None
        if not host:
            logger.warning("Blocked egress to a URL with no resolvable host")
            raise EgressBlockedError("Egress blocked: destination URL has no host.")
        self.check_host(host)

    @classmethod
    def for_run(
        cls,
        *,
        target_hosts: Iterable[str],
        provider_host: str | None = None,
        extra_allowed: Iterable[str] = (),
    ) -> EgressPolicy:
        """Build the allow-list from the target, the provider, and user extras."""

        hosts: set[str] = {h for h in target_hosts if h}
        if provider_host:
            hosts.add(provider_host)
        hosts.update(h for h in extra_allowed if h)
        return cls(hosts)


def provider_host_from_config(provider: str, ollama_host: str | None) -> str | None:
    """Return the host to allow-list for the configured provider, or ``None``.

    For ``ollama`` the host is taken from the configured ``OLLAMA_HOST``; for a
    cloud provider it is that provider's default API hostname. An unknown
    provider returns ``None`` (nothing extra is allowed — fail closed).
    """

    normalized = provider.strip().lower()
    if normalized == "ollama":
        if not ollama_host:
            return None
        try:
            return urlsplit(ollama_host).hostname
        except ValueError:
            return None
    return _CLOUD_PROVIDER_HOSTS.get(normalized)
