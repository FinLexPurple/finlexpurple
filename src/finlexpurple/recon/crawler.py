"""Bounded HTTP crawler that checks confirmed scope before every connection."""

from __future__ import annotations

import ipaddress
import logging
import socket
import time
from collections import deque
from dataclasses import dataclass
from html.parser import HTMLParser
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from finlexpurple.logging_setup import RedactionFilter
from finlexpurple.recon.endpoint_catalog import EndpointCatalog
from finlexpurple.recon.fingerprint import Fingerprint, identify
from finlexpurple.scope.enforcement import OutOfScopeError, enforce_scope
from finlexpurple.scope.models import InvalidTargetError, ScopeDefinition, Target

logger = logging.getLogger(__name__)
_httpx_logger = logging.getLogger("httpx")
# HTTPX emits request URLs at INFO, including raw query values. Keep those
# third-party request lines out of logs; our own messages use redact_url().
_httpx_logger.setLevel(max(_httpx_logger.level, logging.WARNING))
if not any(isinstance(item, RedactionFilter) for item in _httpx_logger.filters):
    _httpx_logger.addFilter(RedactionFilter())
USER_AGENT = "FinLexPurple/0.1.0a1 (authorized security reconnaissance)"
_HTML_TYPES = {"text/html", "application/xhtml+xml"}
_REDIRECT_STATUSES = {301, 302, 303, 307, 308}


class ReconError(ValueError):
    """Recon could not safely use the supplied root or configuration."""


@dataclass(frozen=True)
class ReconResult:
    """Endpoint, fingerprint, robots hints, and bounded run statistics."""

    catalog: EndpointCatalog
    fingerprint: Fingerprint
    disallow_paths: tuple[str, ...]
    requests_made: int
    pages_visited: int
    warnings: tuple[str, ...]


@dataclass(frozen=True)
class _Page:
    url: str
    depth: int


class _PageParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.forms: list[tuple[str, str, set[str]]] = []
        self._form: tuple[str, str, set[str]] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        values = dict(attrs)
        if tag in {"a", "area"} and values.get("href"):
            self.links.append(values["href"] or "")
        if tag == "form":
            self._form = (values.get("action") or "", (values.get("method") or "GET").upper(), set())
        elif tag in {"input", "select", "textarea", "button"} and self._form:
            name = values.get("name")
            if name:
                self._form[2].add(name)

    def handle_endtag(self, tag: str) -> None:
        if tag == "form" and self._form:
            action, method, parameters = self._form
            self.forms.append((action, method, parameters))
            self._form = None


def redact_url(url: str) -> str:
    """Keep query parameter names for diagnostics while removing every value."""

    try:
        parsed = urlsplit(url)
    except ValueError:
        return "<invalid-url>"
    if not parsed.query:
        return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
    redacted = "&".join(f"{part.split('=', 1)[0]}=[REDACTED]" for part in parsed.query.split("&"))
    return urlunsplit((parsed.scheme, parsed.netloc, parsed.path, redacted, ""))


def _validated_url(url: str) -> tuple[str, str, int, str, str]:
    try:
        parts = urlsplit(url)
        port = parts.port or (443 if parts.scheme.lower() == "https" else 80)
    except ValueError:
        raise ReconError("Recon URL has invalid authority or port syntax.") from None
    scheme = parts.scheme.lower()
    if scheme not in {"http", "https"} or not parts.hostname:
        raise ReconError("Recon follows only HTTP and HTTPS URLs with a hostname.")
    if parts.username is not None or parts.password is not None:
        raise ReconError("Recon URLs cannot contain embedded credentials.")
    try:
        canonical_target = Target.parse(
            urlunsplit((scheme, parts.netloc, parts.path or "/", "", ""))
        )
    except InvalidTargetError:
        raise ReconError("Recon URL has an invalid hostname or path.") from None
    return (
        scheme,
        canonical_target.host or "",
        port,
        canonical_target.path or "/",
        parts.query,
    )


def _url_for_scope(scope: ScopeDefinition, url: str) -> None:
    scheme, _, _, _, _ = _validated_url(url)
    if scope.target.kind == "network":
        # Network authorization is checked against each resolved peer IP below.
        return
    if scope.target.kind != "url":
        raise ReconError("Web recon requires a confirmed URL or IP/CIDR scope.")
    enforce_scope(scope, url)
    if scheme != scope.target.scheme:
        raise OutOfScopeError("Action blocked: destination is outside the confirmed scope.")


def _resolved_addresses(scope: ScopeDefinition, url: str) -> list[str]:
    _, hostname, port, _, _ = _validated_url(url)
    try:
        records = socket.getaddrinfo(hostname, port, type=socket.SOCK_STREAM)
    except OSError:
        logger.warning("Recon could not resolve %s", redact_url(url))
        return []
    addresses: list[str] = []
    for record in records:
        address = str(record[4][0]).split("%", maxsplit=1)[0]
        try:
            canonical = ipaddress.ip_address(address).compressed
        except ValueError:
            continue
        if canonical in addresses:
            continue
        if scope.target.kind == "network":
            try:
                enforce_scope(scope, canonical)
            except OutOfScopeError:
                continue
        addresses.append(canonical)
    if not addresses:
        logger.warning("Recon found no permitted address for %s", redact_url(url))
    return addresses


def _pinned_url(url: str, address: str) -> tuple[str, str]:
    scheme, hostname, port, path, query = _validated_url(url)
    ip = ipaddress.ip_address(address)
    netloc_host = f"[{ip.compressed}]" if ip.version == 6 else ip.compressed
    default_port = 443 if scheme == "https" else 80
    netloc = netloc_host if port == default_port else f"{netloc_host}:{port}"
    wire_url = urlunsplit((scheme, netloc, path, query, ""))
    original_host = f"[{hostname}]" if ":" in hostname else hostname
    original_authority = original_host if port == default_port else f"{original_host}:{port}"
    return wire_url, original_authority


def _request(
    scope: ScopeDefinition,
    url: str,
    *,
    timeout: float,
    max_response_bytes: int,
) -> tuple[int, dict[str, str], bytes] | None:
    _url_for_scope(scope, url)
    addresses = _resolved_addresses(scope, url)
    if not addresses:
        return None
    address = addresses[0]
    wire_url, original_authority = _pinned_url(url, address)
    _, hostname, _, _, _ = _validated_url(url)
    headers = {
        "Host": original_authority,
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml;q=0.9,*/*;q=0.1",
    }
    extensions: dict[str, object] = {}
    if urlsplit(url).scheme.lower() == "https" and not _is_ip_literal(hostname):
        # The installed httpcore connection uses this extension for TLS SNI and
        # hostname validation while the TCP connection is pinned to a checked IP.
        extensions["sni_hostname"] = hostname
    request = httpx.Request("GET", wire_url, headers=headers, extensions=extensions)
    logger.info("Recon GET %s", redact_url(url))
    try:
        with httpx.Client(
            follow_redirects=False,
            trust_env=False,
            timeout=timeout,
        ) as client:
            response = client.send(request, stream=True)
            try:
                remote = response.extensions.get("network_stream")
                actual = None
                if remote is not None:
                    actual = remote.get_extra_info("server_addr")
                if scope.target.kind == "network" and not actual:
                    logger.warning("Recon could not verify the connected peer for %s", redact_url(url))
                    return None
                if actual:
                    try:
                        actual_ip = ipaddress.ip_address(str(actual[0]).split("%", 1)[0])
                    except (IndexError, ValueError, TypeError):
                        logger.warning("Recon could not verify the connected peer for %s", redact_url(url))
                        return None
                    if actual_ip != ipaddress.ip_address(address):
                        logger.warning("Recon peer differed from checked address for %s", redact_url(url))
                        return None
                    if actual and scope.target.kind == "network":
                        enforce_scope(scope, actual_ip.compressed)
                body = bytearray()
                content_length = response.headers.get("content-length")
                if content_length and content_length.isdecimal() and int(content_length) > max_response_bytes:
                    logger.info("Recon response exceeded the size limit for %s", redact_url(url))
                else:
                    for chunk in response.iter_bytes():
                        remaining = max_response_bytes - len(body)
                        if remaining <= 0:
                            break
                        body.extend(chunk[:remaining])
                        if len(chunk) > remaining:
                            break
                return response.status_code, dict(response.headers), bytes(body)
            finally:
                response.close()
    except (httpx.HTTPError, OSError, OutOfScopeError) as exc:
        logger.warning("Recon request failed for %s (%s)", redact_url(url), type(exc).__name__)
        return None


def _canonical_candidate(base_url: str, href: str) -> str | None:
    joined = urljoin(base_url, href.strip())
    try:
        scheme, hostname, port, path, query = _validated_url(joined)
    except ReconError:
        return None
    authority_host = f"[{hostname}]" if ":" in hostname else hostname.lower()
    default_port = 443 if scheme == "https" else 80
    authority = authority_host if port == default_port else f"{authority_host}:{port}"
    return urlunsplit((scheme, authority, path, query, ""))


def _parse_robots(body: bytes) -> tuple[str, ...]:
    disallowed: list[str] = []
    try:
        text = body.decode("utf-8", errors="replace")
    except (AttributeError, UnicodeError):
        return ()
    for line in text.splitlines():
        directive, separator, value = line.partition(":")
        if separator and directive.strip().lower() == "disallow":
            path = value.split("#", maxsplit=1)[0].strip()
            if path and path not in disallowed:
                disallowed.append(path)
    return tuple(disallowed)


def _robots_blocks(url: str, disallow_paths: tuple[str, ...]) -> bool:
    path = urlsplit(url).path or "/"
    return any(path.startswith(item.rstrip("*") or "/") for item in disallow_paths)


def _merge_fingerprints(old: Fingerprint, new: Fingerprint) -> Fingerprint:
    return Fingerprint(
        server=old.server or new.server,
        technologies=tuple(sorted(set(old.technologies) | set(new.technologies))),
    )


def run_recon(
    scope: ScopeDefinition,
    root_url: str,
    *,
    max_pages: int = 100,
    max_depth: int = 3,
    request_timeout: float = 10.0,
    max_response_bytes: int = 2 * 1024 * 1024,
    max_redirects: int = 5,
    max_requests: int = 200,
    request_delay: float = 0.5,
    respect_robots: bool = False,
) -> ReconResult:
    """Crawl the in-scope URL tree with strict bounds and no form submission."""

    if max_pages < 1 or max_depth < 0 or max_requests < 1:
        raise ReconError("Page and request limits must be positive; depth cannot be negative.")
    if request_timeout <= 0 or max_response_bytes < 1 or max_redirects < 0:
        raise ReconError("Timeout, response size, and redirect limits must be positive.")
    if request_delay < 0 or request_delay > 60:
        raise ReconError("Request delay must be between 0 and 60 seconds.")
    root = _canonical_candidate(root_url, "")
    if root is None:
        raise ReconError("Recon root must be a valid HTTP or HTTPS URL.")
    _url_for_scope(scope, root)
    if scope.target.kind == "directory":
        raise ReconError("Web recon does not support local directory scopes.")

    catalog = EndpointCatalog()
    fingerprint = Fingerprint(server=None, technologies=())
    warnings: list[str] = []
    disallow_paths: tuple[str, ...] = ()
    requests_made = 0
    pages_visited = 0
    last_request_at: float | None = None

    def fetch(url: str) -> tuple[str, int, dict[str, str], bytes] | None:
        nonlocal requests_made, last_request_at
        current = url
        for redirects in range(max_redirects + 1):
            _url_for_scope(scope, current)
            if requests_made >= max_requests:
                warnings.append("Recon request limit reached.")
                return None
            if last_request_at is not None and request_delay:
                time.sleep(max(0.0, request_delay - (time.monotonic() - last_request_at)))
            response = _request(
                scope,
                current,
                timeout=request_timeout,
                max_response_bytes=max_response_bytes,
            )
            last_request_at = time.monotonic()
            requests_made += 1
            if response is None:
                return None
            status, headers, body = response
            if status not in _REDIRECT_STATUSES:
                return current, status, headers, body
            location = headers.get("location")
            if not location:
                return current, status, headers, body
            candidate = _canonical_candidate(current, location)
            if candidate is None:
                return current, status, headers, body
            try:
                # Enforce the next hop before its address resolution or request.
                _url_for_scope(scope, candidate)
            except OutOfScopeError:
                logger.warning("Blocked out-of-scope redirect to %s", redact_url(candidate))
                return current, status, headers, body
            if redirects == max_redirects:
                warnings.append("Redirect limit reached.")
                return current, status, headers, body
            current = candidate
        return None

    robots_url = urljoin(root, "/robots.txt")
    try:
        _url_for_scope(scope, robots_url)
    except OutOfScopeError:
        warnings.append("robots.txt is outside the confirmed path scope and was not requested.")
    else:
        robots_response = fetch(robots_url)
        if robots_response is not None:
            _, _, headers, body = robots_response
            if headers.get("content-type", "").split(";", 1)[0].strip().lower() in _HTML_TYPES | {"text/plain"}:
                disallow_paths = _parse_robots(body)

    queue: deque[_Page] = deque([_Page(root, 0)])
    queued = {root}
    visited: set[str] = set()
    while queue and pages_visited < max_pages:
        page = queue.popleft()
        if page.url in visited:
            continue
        visited.add(page.url)
        if respect_robots and _robots_blocks(page.url, disallow_paths):
            logger.info("Skipped robots-disallowed path %s", redact_url(page.url))
            continue
        fetched = fetch(page.url)
        if fetched is None:
            continue
        final_url, _, headers, body = fetched
        content_type = headers.get("content-type", "").split(";", 1)[0].strip().lower() or None
        catalog.add("GET", page.url, content_type=content_type)
        pages_visited += 1
        if content_type not in _HTML_TYPES:
            continue
        page_fingerprint = identify(headers, body.decode("utf-8", errors="replace"))
        fingerprint = _merge_fingerprints(fingerprint, page_fingerprint)
        parser = _PageParser()
        parser.feed(body.decode("utf-8", errors="replace"))
        for action, method, parameters in parser.forms:
            form_url = _canonical_candidate(final_url, action or final_url)
            if form_url is None:
                continue
            try:
                _url_for_scope(scope, form_url)
            except OutOfScopeError:
                continue
            catalog.add(method, form_url, parameters=parameters)
        if page.depth >= max_depth:
            continue
        for href in parser.links:
            candidate = _canonical_candidate(final_url, href)
            if candidate is None or candidate in queued:
                continue
            try:
                # Scope is checked on every discovered destination before queuing.
                _url_for_scope(scope, candidate)
            except OutOfScopeError:
                continue
            if respect_robots and _robots_blocks(candidate, disallow_paths):
                continue
            if len(queued) >= max_requests:
                if "Recon discovery queue limit reached." not in warnings:
                    warnings.append("Recon discovery queue limit reached.")
                break
            queued.add(candidate)
            queue.append(_Page(candidate, page.depth + 1))

    if queue and pages_visited >= max_pages:
        warnings.append("Recon page limit reached.")
    return ReconResult(
        catalog=catalog,
        fingerprint=fingerprint,
        disallow_paths=disallow_paths,
        requests_made=requests_made,
        pages_visited=pages_visited,
        warnings=tuple(warnings),
    )


def _is_ip_literal(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False
    return True
