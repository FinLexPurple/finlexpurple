"""Canonical target and explicit scope models."""

from __future__ import annotations

import ipaddress
import os
import posixpath
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal
from urllib.parse import unquote, urlsplit

from pydantic import BaseModel, ConfigDict


class InvalidTargetError(ValueError):
    """The supplied target is ambiguous or unsupported."""


def _canonical_url_path(raw_path: str) -> str:
    if re.search(r"%(?:2f|5c)", raw_path, re.IGNORECASE):
        raise InvalidTargetError("URL paths cannot contain encoded separators.")
    decoded = unquote(raw_path or "/")
    if "\\" in decoded or any(ord(char) < 32 for char in decoded):
        raise InvalidTargetError("URL paths cannot contain backslashes or control characters.")
    normalized = posixpath.normpath("/" + decoded.lstrip("/"))
    if decoded.endswith("/") and normalized != "/":
        normalized += "/"
    return normalized


def _canonical_hostname(hostname: str) -> str:
    if not hostname or "%" in hostname:
        raise InvalidTargetError("A valid URL hostname is required.")
    try:
        return ipaddress.ip_address(hostname).compressed.lower()
    except ValueError:
        try:
            canonical = hostname.rstrip(".").encode("idna").decode("ascii").lower()
        except UnicodeError:
            raise InvalidTargetError("The URL hostname is invalid.") from None
        labels = canonical.split(".")
        if any(not label or len(label) > 63 or not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in labels):
            raise InvalidTargetError("The URL hostname is invalid.")
        return canonical


class Target(BaseModel):
    """A normalized web URL, IP network, or existing local directory."""

    model_config = ConfigDict(frozen=True)

    kind: Literal["url", "network", "directory"]
    canonical: str
    host: str | None = None
    scheme: str | None = None
    port: int | None = None
    path: str | None = None
    network: str | None = None
    local_path: Path | None = None

    @classmethod
    def parse(cls, value: str | os.PathLike[str]) -> Target:
        """Validate and canonicalize a URL, IP/CIDR, or existing directory."""

        raw = os.fspath(value).strip()
        if not raw:
            raise InvalidTargetError("Target cannot be empty.")
        if "://" in raw:
            return cls._parse_url(raw)
        try:
            address = ipaddress.ip_address(raw)
        except ValueError:
            address = None
        if address is not None:
            network = ipaddress.ip_network(f"{address}/{address.max_prefixlen}")
            return cls(kind="network", canonical=network.with_prefixlen, network=network.with_prefixlen)
        try:
            network = ipaddress.ip_network(raw, strict=False)
        except ValueError:
            network = None
        if network is not None:
            return cls(kind="network", canonical=network.with_prefixlen, network=network.with_prefixlen)
        try:
            local_path = Path(raw).expanduser().resolve(strict=True)
        except (OSError, RuntimeError):
            raise InvalidTargetError("Target must be an existing local directory.") from None
        if not local_path.is_dir():
            raise InvalidTargetError("Target must be an existing local directory.")
        canonical = os.path.normcase(str(local_path))
        return cls(kind="directory", canonical=canonical, local_path=Path(canonical))

    @classmethod
    def _parse_url(cls, raw: str) -> Target:
        try:
            parsed = urlsplit(raw)
            port = parsed.port
        except ValueError:
            raise InvalidTargetError("The target URL has invalid authority or port syntax.") from None
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.netloc:
            raise InvalidTargetError("Target URL must use HTTP or HTTPS and include a hostname.")
        if parsed.username is not None or parsed.password is not None:
            raise InvalidTargetError("Target URLs cannot contain embedded credentials.")
        if parsed.query or parsed.fragment:
            raise InvalidTargetError("Target URLs cannot contain a query or fragment.")
        host = _canonical_hostname(parsed.hostname or "")
        scheme = parsed.scheme.lower()
        if port == (80 if scheme == "http" else 443):
            port = None
        path = _canonical_url_path(parsed.path)
        authority_host = f"[{host}]" if ":" in host else host
        authority = authority_host if port is None else f"{authority_host}:{port}"
        canonical = f"{scheme}://{authority}{path}"
        return cls(
            kind="url",
            canonical=canonical,
            host=host,
            scheme=scheme,
            port=port,
            path=path,
        )


class ScopeDefinition(BaseModel):
    """An explicit target allow-list and deny-list with confirmation metadata."""

    model_config = ConfigDict(frozen=True)

    target: Target
    allow_hosts: tuple[str, ...] = ()
    allow_networks: tuple[str, ...] = ()
    allow_paths: tuple[str, ...] = ()
    deny_hosts: tuple[str, ...] = ()
    deny_networks: tuple[str, ...] = ()
    deny_paths: tuple[str, ...] = ()
    first_confirmed_at: datetime | None = None

    @classmethod
    def for_target(cls, target: Target, *, first_confirmed_at: datetime | None = None) -> ScopeDefinition:
        """Create an exact-target allow-list; denials take precedence at enforcement."""

        common = {"target": target, "first_confirmed_at": first_confirmed_at}
        if target.kind == "url":
            return cls(**common, allow_hosts=(target.host or "",), allow_paths=(target.path or "/",))
        if target.kind == "network":
            return cls(**common, allow_networks=(target.network or "",))
        return cls(**common, allow_paths=(str(target.local_path),))

    def confirmed(self, timestamp: datetime | None = None) -> ScopeDefinition:
        """Return a copy carrying a UTC confirmation timestamp."""

        return self.model_copy(
            update={"first_confirmed_at": timestamp or datetime.now(timezone.utc)}
        )
