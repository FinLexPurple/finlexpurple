"""Tests for environment configuration and validation."""

from __future__ import annotations

import os

import pytest

from finlexpurple.config import Config, ConfigurationError

_VARIABLES = (
    "LLM_PROVIDER",
    "OLLAMA_MODEL",
    "OLLAMA_HOST",
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "OPENROUTER_API_KEY",
    "GEMINI_API_KEY",
    "REQUIRE_HUMAN_APPROVAL",
    "TELEMETRY_ENABLED",
)


@pytest.fixture(autouse=True)
def clean_config_environment(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _VARIABLES:
        monkeypatch.delenv(name, raising=False)


def test_loads_dotenv_from_explicit_current_directory(tmp_path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("LLM_PROVIDER=ollama\nOLLAMA_MODEL=local-test\n", encoding="utf-8")

    config = Config.load(env_file)

    assert config.ollama_model == "local-test"


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
