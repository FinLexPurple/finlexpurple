"""Decision 2 Step 2: baked pull defaults + env overrides, fail-closed when cleared."""

from __future__ import annotations

import pytest

from finlexpurple.intel import config


def test_baked_defaults_pin_the_publisher_regexp_with_no_config() -> None:
    channel = config.resolve_pull_channel(env={})
    assert channel.pack_url == config.DEFAULT_PACKS_URL
    assert channel.signature_url == config.DEFAULT_SIG_URL
    assert channel.expected_identity.identity is None  # regexp mode by default
    assert channel.expected_identity.identity_regexp == config.DEFAULT_PINNED_IDENTITY_REGEXP
    assert channel.expected_identity.issuer == config.DEFAULT_OIDC_ISSUER
    assert channel.expected_sha256 is None  # optional extra pin, unset
    assert "github.com" in channel.egress_hosts


def test_exact_identity_override_switches_to_exact_pin() -> None:
    channel = config.resolve_pull_channel(env={config.ENV_IDENTITY: "https://example/wf.yml@refs/tags/v9"})
    assert channel.expected_identity.identity == "https://example/wf.yml@refs/tags/v9"
    assert channel.expected_identity.identity_regexp is None


def test_cleared_identity_fails_closed() -> None:
    with pytest.raises(config.ConfigError, match="identity pin"):
        config.resolve_pull_channel(env={config.ENV_IDENTITY: "   "})


def test_cleared_url_fails_closed() -> None:
    with pytest.raises(config.ConfigError, match="fail-closed"):
        config.resolve_pull_channel(env={config.ENV_URL: ""})


def test_sha_override_is_an_optional_extra_pin() -> None:
    pinned = config.resolve_pull_channel(env={config.ENV_SHA: "sha256:" + "a" * 64})
    assert pinned.expected_sha256 == "sha256:" + "a" * 64
    cleared = config.resolve_pull_channel(env={config.ENV_SHA: ""})
    assert cleared.expected_sha256 is None  # clearing the optional pin is allowed, not fail-closed


def test_extra_egress_hosts_are_added_to_the_allowlist() -> None:
    channel = config.resolve_pull_channel(
        env={config.ENV_EGRESS_HOSTS: "assets.example , cdn.example"}
    )
    assert "assets.example" in channel.egress_hosts
    assert "cdn.example" in channel.egress_hosts
    assert "github.com" in channel.egress_hosts  # channel host is always present
