"""Tests for configured provider selection."""

from __future__ import annotations

import pytest

from finlexpurple.config import Config
from finlexpurple.config import LLMProvider as ProviderName
from finlexpurple.providers.anthropic_provider import AnthropicProvider
from finlexpurple.providers.base import (
    MissingAPIKeyError,
    MissingModelError,
    UnsupportedProviderError,
)
from finlexpurple.providers.factory import create_provider
from finlexpurple.providers.gemini_provider import GeminiProvider
from finlexpurple.providers.ollama_provider import OllamaProvider
from finlexpurple.providers.openai_provider import OpenAIProvider
from finlexpurple.providers.openrouter_provider import OpenRouterProvider


@pytest.mark.parametrize(
    ("provider", "expected_type", "settings"),
    [
        (
            ProviderName.OLLAMA,
            OllamaProvider,
            {"ollama_model": "local-test", "ollama_host": "http://localhost:11434"},
        ),
        (
            ProviderName.ANTHROPIC,
            AnthropicProvider,
            {"anthropic_api_key": "test", "anthropic_model": "claude-test"},
        ),
        (
            ProviderName.OPENAI,
            OpenAIProvider,
            {"openai_api_key": "test", "openai_model": "gpt-test"},
        ),
        (
            ProviderName.OPENROUTER,
            OpenRouterProvider,
            {"openrouter_api_key": "test", "openrouter_model": "provider/test"},
        ),
        (
            ProviderName.GEMINI,
            GeminiProvider,
            {"gemini_api_key": "test", "gemini_model": "gemini-test"},
        ),
    ],
)
def test_factory_selects_configured_provider(provider, expected_type, settings) -> None:
    config = Config.model_construct(llm_provider=provider, **settings)

    assert isinstance(create_provider(config), expected_type)


def test_factory_rejects_unknown_provider_value() -> None:
    config = Config.model_construct(llm_provider="unsupported")

    with pytest.raises(UnsupportedProviderError, match="unsupported"):
        create_provider(config)


def test_factory_preserves_distinct_missing_configuration_errors() -> None:
    cloud_config = Config.model_construct(
        llm_provider=ProviderName.OPENAI,
        openai_api_key=None,
        openai_model="gpt-test",
    )
    ollama_config = Config.model_construct(llm_provider=ProviderName.OLLAMA, ollama_model=None)

    with pytest.raises(MissingAPIKeyError):
        create_provider(cloud_config)
    with pytest.raises(MissingModelError):
        create_provider(ollama_config)
