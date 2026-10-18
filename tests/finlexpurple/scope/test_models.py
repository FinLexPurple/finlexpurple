"""Synthetic tests for target canonicalization and scope construction."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest

from finlexpurple.scope.models import InvalidTargetError, ScopeDefinition, Target


@pytest.mark.parametrize(
    ("raw", "canonical", "host", "path", "port"),
    [
        ("HTTPS://ExAmPlE.COM:443/a/../app/", "https://example.com/app/", "example.com", "/app/", None),
        ("http://example.com:8080/app", "http://example.com:8080/app", "example.com", "/app", 8080),
        ("https://example.com/a%20folder", "https://example.com/a%20folder", "example.com", "/a%20folder", None),
        ("https://[2001:db8::1]/", "https://[2001:db8::1]/", "2001:db8::1", "/", None),
    ],
)
def test_url_targets_are_canonicalized(raw, canonical, host, path, port) -> None:
    target = Target.parse(raw)

    assert target.kind == "url"
    assert target.canonical == canonical
    assert target.host == host
    assert target.path == path
    assert target.port == port


@pytest.mark.parametrize(
    ("raw", "canonical"),
    [
        ("192.0.2.7", "192.0.2.7/32"),
        ("192.0.2.7/24", "192.0.2.0/24"),
        ("2001:db8::/64", "2001:db8::/64"),
    ],
)
def test_ip_target_is_canonical_network(raw, canonical) -> None:
    target = Target.parse(raw)

    assert target.kind == "network"
    assert target.network == canonical
    assert target.canonical == canonical


def test_directory_target_resolves_symlinks_and_requires_existing_directory(tmp_path) -> None:
    root = tmp_path / "project"
    root.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(root, target_is_directory=True)

    target = Target.parse(alias)

    assert target.kind == "directory"
    assert target.local_path == root.resolve()
    with pytest.raises(InvalidTargetError, match="existing local directory"):
        Target.parse(tmp_path / "missing")
    with pytest.raises(InvalidTargetError, match="existing local directory"):
        Target.parse(root / "file.txt")


@pytest.mark.parametrize(
    "raw",
    [
        "ftp://example.com/",
        "https://user:password@example.com/",
        "https://example.com/path?query=value",
        "https://example.com/path#fragment",
        "https://example.com/a%2fb",
        "https://bad host/",
    ],
)
def test_ambiguous_or_unsupported_targets_are_rejected(raw: str) -> None:
    with pytest.raises(InvalidTargetError):
        Target.parse(raw)


def test_scope_is_exact_target_and_records_confirmation_timestamp() -> None:
    target = Target.parse("https://example.com/app")
    initial = ScopeDefinition.for_target(target)
    confirmed_at = datetime(2026, 1, 2, tzinfo=timezone.utc)
    confirmed = initial.confirmed(confirmed_at)

    assert initial.allow_hosts == ("example.com",)
    assert initial.allow_paths == ("/app",)
    assert initial.deny_hosts == initial.deny_paths == ()
    assert confirmed.first_confirmed_at == confirmed_at
