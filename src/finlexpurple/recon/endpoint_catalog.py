"""Structured, de-duplicated endpoint observations produced by recon."""

from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit, urlunsplit


def _catalog_url(url: str) -> str:
    parsed = urlsplit(url)
    return urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path or "/", "", ""))


def _query_names(url: str) -> set[str]:
    return {key for key, _ in parse_qsl(urlsplit(url).query, keep_blank_values=True) if key}


@dataclass(frozen=True)
class Endpoint:
    """One method and URL path, with parameter names but no observed values."""

    method: str
    url: str
    parameters: tuple[str, ...] = ()
    content_type: str | None = None


@dataclass
class EndpointCatalog:
    """Merge duplicate observations while keeping query values out of storage."""

    _endpoints: dict[tuple[str, str], Endpoint] = field(default_factory=dict)

    def add(
        self,
        method: str,
        url: str,
        *,
        parameters: set[str] | None = None,
        content_type: str | None = None,
    ) -> None:
        normalized_method = method.upper()
        normalized_url = _catalog_url(url)
        key = (normalized_method, normalized_url)
        old = self._endpoints.get(key)
        names = _query_names(url) | (parameters or set())
        if old is not None:
            names.update(old.parameters)
        self._endpoints[key] = Endpoint(
            method=normalized_method,
            url=normalized_url,
            parameters=tuple(sorted(names)),
            content_type=content_type or (old.content_type if old else None),
        )

    @property
    def endpoints(self) -> tuple[Endpoint, ...]:
        """Return the catalog in stable URL/method order."""

        return tuple(self._endpoints[key] for key in sorted(self._endpoints))

    def __len__(self) -> int:
        return len(self._endpoints)
