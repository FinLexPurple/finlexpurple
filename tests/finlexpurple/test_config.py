"""Tests for environment configuration and validation."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from finlexpurple.config import Config, ConfigurationError

_VARIABLES = (
    "LLM_PROVIDER",
    "OLLAMA_MODEL",
    "OLLAMA_HOST",
    "ANTHROPIC_MODEL",
    "OPENAI_MODEL",
    "OPENROUTER_MODEL",
    "GEMINI_MODEL",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "OPENROUTER_API_KEY",
    "GEMINI_API_KEY",
    "REQUIRE_HUMAN_APPROVAL",
    "TELEMETRY_ENABLED",
    "MODEL_TIER",
    "FALLBACK_LLM_PROVIDER",
    "MAX_SPEND_USD",
    # Unit 1.4 canonical FLP_-prefixed names (cleared too, so tests are isolated).
    "FLP_LLM_PROVIDER",
    "FLP_OLLAMA_MODEL",
    "FLP_OLLAMA_HOST",
    "FLP_ANTHROPIC_MODEL",
    "FLP_OPENAI_MODEL",
    "FLP_OPENROUTER_MODEL",
    "FLP_GEMINI_MODEL",
    "FLP_FALLBACK_LLM_PROVIDER",
    "FLP_MODEL_TIER",
    "FLP_REQUIRE_HUMAN_APPROVAL",
    "FLP_MAX_SPEND_USD",
)


@pytest.fixture(autouse=True)
def clean_config_environment(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    # Isolate from the ambient config environment in two ways: clear any config
    # variables that leak in from the shell, and run the test from an empty
    # directory. The second matters because Config uses pydantic-settings'
    # env_file=".env", which reads the *current directory's* .env — so without
    # this, a .env in the repo root (created by `finlexpurple init`/`setup`)
    # would bleed into these tests. Tests that need a .env create their own
    # under tmp_path (now the cwd) and pass it explicitly.
    for name in _VARIABLES:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)


def test_loads_dotenv_from_explicit_current_directory(tmp_path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("LLM_PROVIDER=ollama\nOLLAMA_MODEL=local-test\n", encoding="utf-8")

    config = Config.load(env_file)

    assert config.ollama_model == "local-test"


def test_flp_prefixed_env_names_are_accepted(tmp_path) -> None:
    """Unit 1.4: the canonical FLP_-prefixed names are honoured."""

    env_file = tmp_path / ".env"
    env_file.write_text(
        "FLP_LLM_PROVIDER=ollama\nFLP_OLLAMA_MODEL=flp-model\nFLP_MAX_SPEND_USD=3.50\n",
        encoding="utf-8",
    )
    config = Config.load(env_file)
    assert config.ollama_model == "flp-model"
    assert config.max_spend_usd == 3.50


def test_legacy_bare_env_names_still_accepted(tmp_path) -> None:
    """Back-compat: a pre-0.4.0 .env with bare names keeps working."""

    env_file = tmp_path / ".env"
    env_file.write_text("OLLAMA_MODEL=legacy-model\nMAX_SPEND_USD=2.0\n", encoding="utf-8")
    config = Config.load(env_file)
    assert config.ollama_model == "legacy-model"
    assert config.max_spend_usd == 2.0


def test_flp_name_preferred_when_both_present(tmp_path) -> None:
    """When both the FLP_ name and its legacy alias are set, the canonical one wins."""

    env_file = tmp_path / ".env"
    env_file.write_text("OLLAMA_MODEL=legacy\nFLP_OLLAMA_MODEL=canonical\n", encoding="utf-8")
    assert Config.load(env_file).ollama_model == "canonical"


def test_api_keys_keep_their_standard_unprefixed_names(tmp_path) -> None:
    """Provider API keys keep their conventional, un-prefixed names."""

    env_file = tmp_path / ".env"
    env_file.write_text("ANTHROPIC_API_KEY=sk-standard\n", encoding="utf-8")
    assert Config.load(env_file).anthropic_api_key == "sk-standard"


def test_provider_models_have_overridable_defaults(tmp_path) -> None:
    defaults = Config.load(tmp_path / ".env")
    assert defaults.anthropic_model == "claude-sonnet-5-5"
    assert defaults.openai_model == "gpt-6.1-sol"
    assert defaults.openrouter_model == "openai/gpt-6-luna"
    assert defaults.gemini_model == "gemini-3.8-flash"

    env_file = tmp_path / "models.env"
    env_file.write_text(
        "ANTHROPIC_MODEL=custom-claude\nOPENAI_MODEL=custom-gpt\n"
        "OPENROUTER_MODEL=custom/route\nGEMINI_MODEL=custom-gemini\n",
        encoding="utf-8",
    )
    overridden = Config.load(env_file)
    assert overridden.anthropic_model == "custom-claude"
    assert overridden.openai_model == "custom-gpt"
    assert overridden.openrouter_model == "custom/route"
    assert overridden.gemini_model == "custom-gemini"


def test_config_constructor_reads_dotenv_from_current_directory(tmp_path, monkeypatch) -> None:
    monkeypatch.chdir(tmp_path)
    (tmp_path / ".env").write_text("OLLAMA_MODEL=from-current-directory\n", encoding="utf-8")

    assert Config().ollama_model == "from-current-directory"


def test_cloud_provider_without_key_names_missing_variable(tmp_path) -> None:
    os.environ["LLM_PROVIDER"] = "openai"

    with pytest.raises(ConfigurationError, match="OPENAI_API_KEY"):
        Config.load(tmp_path / ".env")


def test_unknown_provider_lists_allowed_providers(tmp_path) -> None:
    os.environ["LLM_PROVIDER"] = "unknown-provider"

    with pytest.raises(ConfigurationError) as error:
        Config.load(tmp_path / ".env")

    assert "unknown-provider" in str(error.value)
    assert "ollama, anthropic, openai, openrouter, gemini" in str(error.value)


def test_empty_environment_value_is_treated_as_unset(tmp_path) -> None:
    absent = Config.load(tmp_path / ".env")
    os.environ["TELEMETRY_ENABLED"] = ""
    empty = Config.load(tmp_path / ".env")

    assert absent.telemetry_enabled is empty.telemetry_enabled is False


@pytest.mark.parametrize(("value", "expected"), [("true", True), ("1", True), ("FALSE", False), ("0", False)])
def test_boolean_forms_are_explicitly_parsed(tmp_path, value: str, expected: bool) -> None:
    os.environ["TELEMETRY_ENABLED"] = value

    assert Config.load(tmp_path / ".env").telemetry_enabled is expected


def test_invalid_boolean_names_field_and_value(tmp_path) -> None:
    os.environ["TELEMETRY_ENABLED"] = "sometimes"

    with pytest.raises(ConfigurationError) as error:
        Config.load(tmp_path / ".env")

    assert "TELEMETRY_ENABLED" in str(error.value)
    assert "sometimes" in str(error.value)


def test_model_tier_is_loaded_and_validated(tmp_path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("MODEL_TIER=local-3b-triage\n", encoding="utf-8")

    assert Config.load(env_file).model_tier.value == "local-3b-triage"


def test_empty_model_tier_is_unset_and_invalid_tier_is_specific(tmp_path) -> None:
    os.environ["MODEL_TIER"] = ""
    assert Config.load(tmp_path / ".env").model_tier is None
    os.environ["MODEL_TIER"] = "other-tier"

    with pytest.raises(ConfigurationError) as error:
        Config.load(tmp_path / ".env")

    assert "MODEL_TIER" in str(error.value)
    assert "other-tier" in str(error.value)
    assert "cloud, local-30b, local-8b-hybrid, local-3b-triage" in str(error.value)


def test_optional_cloud_fallback_is_loaded_for_hybrid_tier(tmp_path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "MODEL_TIER=local-8b-hybrid\nFALLBACK_LLM_PROVIDER=openrouter\n"
        "OPENROUTER_API_KEY=test-key\n",
        encoding="utf-8",
    )

    config = Config.load(env_file)

    assert config.fallback_llm_provider.value == "openrouter"
    assert config.llm_provider.value == "ollama"


@pytest.mark.parametrize(
    ("tier", "primary", "fallback", "key", "message"),
    [
        ("local-8b-hybrid", "ollama", "ollama", "", "allowed cloud providers"),
        ("local-8b-hybrid", "ollama", "openai", "", "OPENAI_API_KEY"),
        (
            "local-30b",
            "ollama",
            "openai",
            "key",
            "only supported when MODEL_TIER=local-8b-hybrid",
        ),
        (
            "local-8b-hybrid",
            "openai",
            "openai",
            "key",
            "FALLBACK_LLM_PROVIDER must differ from LLM_PROVIDER",
        ),
    ],
)
def test_invalid_fallback_configuration_is_rejected(
    tmp_path, tier: str, primary: str, fallback: str, key: str, message: str
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        f"MODEL_TIER={tier}\nLLM_PROVIDER={primary}\nFALLBACK_LLM_PROVIDER={fallback}\n"
        f"OPENAI_API_KEY={key}\n",
        encoding="utf-8",
    )

    with pytest.raises(ConfigurationError, match=message):
        Config.load(env_file)
