"""Scope checks that block and log actions outside a confirmed target."""

from __future__ import annotations

import ipaddress
import logging
from pathlib import Path
from urllib.parse import urlsplit

from finlexpurple.scope.models import ScopeDefinition, Target

logger = logging.getLogger(__name__)


class OutOfScopeError(PermissionError):
    """An action was blocked because it falls outside confirmed scope."""


def _path_contains(root: str, candidate: str) -> bool:
    normalized_root = root.rstrip("/") or "/"
    normalized_candidate = candidate.rstrip("/") or "/"
    return normalized_candidate == normalized_root or normalized_candidate.startswith(
        normalized_root.rstrip("/") + "/"
    )


def _deny(scope: ScopeDefinition, detail: str) -> None:
    logger.warning("Blocked out-of-scope action (%s)", detail)
    raise OutOfScopeError("Action blocked: destination is outside the confirmed scope.")


def enforce_scope(scope: ScopeDefinition, destination: str | Path) -> None:
    """Raise ``OutOfScopeError`` unless a URL, IP, or local path is in scope."""

    target = scope.target
    if target.kind == "directory":
        _enforce_directory(scope, destination)
        return
    if isinstance(destination, Path):
        _deny(scope, "filesystem destination for a non-directory target")
    raw = str(destination).strip()
    if target.kind == "network":
        _enforce_network(scope, raw)
        return
    _enforce_url(scope, raw)


def _enforce_directory(scope: ScopeDefinition, destination: str | Path) -> None:
    try:
        candidate = Path(destination).expanduser().resolve(strict=False)
    except (OSError, RuntimeError):
        _deny(scope, "invalid filesystem destination")
    canonical = str(candidate)
    if any(_path_contains(denied, canonical) for denied in scope.deny_paths):
        _deny(scope, "denied filesystem path")
    if any(_path_contains(allowed, canonical) for allowed in scope.allow_paths):
        return
    _deny(scope, "filesystem path outside allowed directory")


def _enforce_network(scope: ScopeDefinition, raw: str) -> None:
    try:
        if "://" in raw:
            parsed = urlsplit(raw)
            address = ipaddress.ip_address(parsed.hostname or "")
        else:
            address = ipaddress.ip_address(raw)
    except ValueError:
        _deny(scope, "destination is not an IP address in the allowed network")
    if any(address in ipaddress.ip_network(network) for network in scope.deny_networks):
        _deny(scope, "denied IP address")
    if any(address in ipaddress.ip_network(network) for network in scope.allow_networks):
        return
    _deny(scope, "IP address outside allowed networks")


def _enforce_url(scope: ScopeDefinition, raw: str) -> None:
    try:
        parsed = urlsplit(raw)
        # Query strings and fragments do not widen host/path authority and are
        # common on scanned URLs, so leave them out of the scope comparison.
        destination = Target.parse(f"{parsed.scheme}://{parsed.netloc}{parsed.path}")
    except ValueError:
        _deny(scope, "invalid URL destination")
    if destination.kind != "url":
        _deny(scope, "URL target requires an HTTP or HTTPS destination")
    host = destination.host or ""
    path = destination.path or "/"
    if host in scope.deny_hosts or any(
        _path_contains(denied, path) for denied in scope.deny_paths
    ):
        _deny(scope, "denied URL host or path")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and any(
        address in ipaddress.ip_network(network) for network in scope.deny_networks
    ):
        _deny(scope, "denied URL IP address")
    if destination.host not in scope.allow_hosts:
        _deny(scope, "URL host outside allow-list")
    target = scope.target
    if destination.scheme != target.scheme or destination.port != target.port:
        _deny(scope, "URL scheme or port differs from confirmed target")
    if not any(_path_contains(allowed, path) for allowed in scope.allow_paths):
        _deny(scope, "URL path outside allow-list")
