"""Phase 7: default-deny egress policy (decisions.md §15).

Proves the policy allows only the target and the configured provider by default,
blocks and logs everything else, and fails closed on malformed/empty hosts.
"""

from __future__ import annotations

import logging

import pytest

from finlexpurple.security.egress_policy import (
    EgressBlockedError,
    EgressPolicy,
    provider_host_from_config,
)


def test_allows_target_and_provider_blocks_everything_else(caplog) -> None:
    policy = EgressPolicy.for_run(
        target_hosts=["example.invalid"], provider_host="api.anthropic.com"
    )
    # Allowed destinations pass silently.
    policy.check_host("example.invalid")
    policy.check_url("https://api.anthropic.com/v1/messages")
    # A third host is blocked and logged.
    with caplog.at_level(logging.WARNING), pytest.raises(EgressBlockedError):
        policy.check_url("https://evil.example.net/steal")
    assert any("Blocked out-of-scope egress" in r.message for r in caplog.records)


def test_host_matching_is_case_and_trailing_dot_insensitive() -> None:
    policy = EgressPolicy.for_run(target_hosts=["Example.Invalid."])
    assert policy.is_allowed_host("example.invalid")
    policy.check_host("EXAMPLE.INVALID")


def test_empty_and_malformed_destinations_fail_closed() -> None:
    policy = EgressPolicy.for_run(target_hosts=["example.invalid"])
    with pytest.raises(EgressBlockedError):
        policy.check_host("")
    with pytest.raises(EgressBlockedError):
        policy.check_host(None)
    with pytest.raises(EgressBlockedError):
        policy.check_url("not-a-url")


def test_extra_allowed_hosts_are_honored() -> None:
    policy = EgressPolicy.for_run(
        target_hosts=["example.invalid"], extra_allowed=["cve.example.org"]
    )
    policy.check_host("cve.example.org")


def test_provider_host_from_config_ollama_uses_configured_host() -> None:
    assert provider_host_from_config("ollama", "http://localhost:11434") == "localhost"
    assert provider_host_from_config("ollama", "") is None


def test_provider_host_from_config_cloud_and_unknown() -> None:
    assert provider_host_from_config("anthropic", None) == "api.anthropic.com"
    assert provider_host_from_config("openai", None) == "api.openai.com"
    # Fail closed: an unknown provider adds nothing to the allow-list.
    assert provider_host_from_config("mystery", None) is None
