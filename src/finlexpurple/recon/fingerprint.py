"""Lightweight fingerprints from response headers and known page signatures."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass


@dataclass(frozen=True)
class Fingerprint:
    """Technologies observed during one recon crawl."""

    server: str | None
    technologies: tuple[str, ...]


def identify(headers: Mapping[str, str], body: str) -> Fingerprint:
    """Identify common web stack markers without executing page scripts."""

    lowered = body.lower()
    found: set[str] = set()
    if "__next_data__" in lowered or "/_next/static/" in lowered or 'id="__next"' in lowered:
        found.add("Next.js")
    if "data-v-" in lowered or "__vue__" in lowered:
        found.add("Vue.js")
    if "ng-version=" in lowered or "ng-version" in lowered:
        found.add("Angular")
    if "/wp-content/" in lowered or "/wp-includes/" in lowered:
        found.add("WordPress")
    if "drupal.settings" in lowered or 'name="generator" content="drupal' in lowered:
        found.add("Drupal")
    return Fingerprint(
        server=headers.get("server"),
        technologies=tuple(sorted(found)),
    )
