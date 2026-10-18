"""Synthetic tests for the scope enforcement guard."""

from __future__ import annotations

import logging

import pytest

from finlexpurple.scope.enforcement import OutOfScopeError, enforce_scope
from finlexpurple.scope.models import ScopeDefinition, Target


def test_url_scope_allows_only_confirmed_host_path_scheme_and_port() -> None:
    scope = ScopeDefinition.for_target(Target.parse("https://example.com/app"))

    assert enforce_scope(scope, "https://example.com/app") is None
    assert enforce_scope(scope, "https://example.com/app/users?id=1") is None

    for destination in (
        "https://sub.example.com/app",
        "https://example.com/application",
        "http://example.com/app",
        "https://example.com:8443/app",
    ):
        with pytest.raises(OutOfScopeError):
            enforce_scope(scope, destination)


def test_deny_rules_take_precedence_over_matching_allow_rules() -> None:
    target = Target.parse("https://example.com/app")
    scope = ScopeDefinition.for_target(target).model_copy(
        update={"deny_hosts": ("example.com",), "deny_paths": ("/app/private",)}
    )

    with pytest.raises(OutOfScopeError):
        enforce_scope(scope, "https://example.com/app")

    host_scope = ScopeDefinition.for_target(target).model_copy(
        update={"deny_paths": ("/app/private",)}
    )
    with pytest.raises(OutOfScopeError):
        enforce_scope(host_scope, "https://example.com/app/private/keys")
    assert enforce_scope(host_scope, "https://example.com/app/public") is None


def test_ip_network_scope_allows_members_and_blocks_outside_addresses(caplog) -> None:
    scope = ScopeDefinition.for_target(Target.parse("192.0.2.0/24"))

    assert enforce_scope(scope, "192.0.2.17") is None
    with (
        caplog.at_level(logging.WARNING),
        pytest.raises(OutOfScopeError, match="outside the confirmed scope"),
    ):
        enforce_scope(scope, "192.0.3.17")

    assert "Blocked out-of-scope action" in caplog.text


def test_ip_deny_network_takes_precedence() -> None:
    scope = ScopeDefinition.for_target(Target.parse("192.0.2.0/24")).model_copy(
        update={"deny_networks": ("192.0.2.16/28",)}
    )

    with pytest.raises(OutOfScopeError):
        enforce_scope(scope, "192.0.2.20")


def test_local_directory_scope_resolves_paths_and_blocks_symlink_escape(tmp_path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    inside = root / "src"
    inside.mkdir()
    outside = tmp_path / "outside"
    outside.mkdir()
    escape = root / "external"
    escape.symlink_to(outside, target_is_directory=True)
    scope = ScopeDefinition.for_target(Target.parse(root))

    assert enforce_scope(scope, inside) is None
    with pytest.raises(OutOfScopeError):
        enforce_scope(scope, escape / "secret.py")


def test_local_path_deny_rule_takes_precedence(tmp_path) -> None:
    root = tmp_path / "workspace"
    root.mkdir()
    private = root / "private"
    private.mkdir()
    scope = ScopeDefinition.for_target(Target.parse(root)).model_copy(
        update={"deny_paths": (str(private.resolve()),)}
    )

    with pytest.raises(OutOfScopeError):
        enforce_scope(scope, private / "key.txt")
