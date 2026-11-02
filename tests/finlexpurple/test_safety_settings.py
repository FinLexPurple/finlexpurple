"""Combined fix Part A: config-swallow fix — safety settings honored or clearly reported.

When Config.load fails (e.g. a cloud provider with no key), the scan/run-agent paths
must NOT silently drop the user's REQUIRE_HUMAN_APPROVAL / MAX_SPEND_USD: they are
recovered from the environment with the same validators, with a loud warning, while
a genuinely unparseable safety value still surfaces its own clear error.
"""

from __future__ import annotations

import pytest

from finlexpurple.cli import _load_safety_settings
from finlexpurple.config import ConfigurationError

# Every config var Config.load reads, cleared so these tests are isolated from any
# env another test leaked (e.g. a stray FALLBACK_LLM_PROVIDER/MODEL_TIER that would
# otherwise make even a plain ollama load fail).
_ALL_CONFIG_KEYS = (
    "LLM_PROVIDER", "OLLAMA_MODEL", "OLLAMA_HOST", "ANTHROPIC_MODEL", "OPENAI_MODEL",
    "OPENROUTER_MODEL", "GEMINI_MODEL", "FALLBACK_LLM_PROVIDER", "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY", "OPENROUTER_API_KEY", "GEMINI_API_KEY", "REQUIRE_HUMAN_APPROVAL",
    "TELEMETRY_ENABLED", "TELEMETRY_ENDPOINT", "MODEL_TIER", "MAX_SPEND_USD",
)


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch, tmp_path):
    # Run in a dir with no .env and a clean slate of every config var.
    monkeypatch.chdir(tmp_path)
    for key in _ALL_CONFIG_KEYS:
        monkeypatch.delenv(key, raising=False)


def test_cloud_provider_without_key_warns_but_honors_require_human_approval(monkeypatch) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")  # cloud provider, NO key
    monkeypatch.setenv("REQUIRE_HUMAN_APPROVAL", "false")
    settings = _load_safety_settings()
    assert settings.config is None  # provider unconfigured -> planning deterministic
    assert settings.require_human_approval is False  # the user's setting is honored, not reset to True
    assert settings.warning and "ANTHROPIC_API_KEY" in settings.warning


def test_valid_config_applies_false_without_warning(monkeypatch) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "ollama")  # no key required
    monkeypatch.setenv("REQUIRE_HUMAN_APPROVAL", "false")
    settings = _load_safety_settings()
    assert settings.config is not None and settings.require_human_approval is False
    assert settings.warning is None


def test_unset_require_human_approval_stays_true(monkeypatch) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    settings = _load_safety_settings()
    assert settings.require_human_approval is True  # §3 default-on


def test_recovers_max_spend_from_env_on_provider_error(monkeypatch) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")  # no key -> load fails
    monkeypatch.setenv("REQUIRE_HUMAN_APPROVAL", "false")
    monkeypatch.setenv("MAX_SPEND_USD", "2.50")
    settings = _load_safety_settings()
    assert settings.require_human_approval is False and settings.max_spend_usd == 2.50


def test_unparseable_require_human_approval_errors_not_silently_defaults(monkeypatch) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "ollama")
    monkeypatch.setenv("REQUIRE_HUMAN_APPROVAL", "maybe")
    with pytest.raises(ConfigurationError, match="REQUIRE_HUMAN_APPROVAL"):
        _load_safety_settings()


def test_unparseable_max_spend_errors(monkeypatch) -> None:
    monkeypatch.setenv("LLM_PROVIDER", "anthropic")  # no key -> load fails, then bad spend surfaces
    monkeypatch.setenv("MAX_SPEND_USD", "abc")
    with pytest.raises(ConfigurationError, match="MAX_SPEND_USD"):
        _load_safety_settings()
