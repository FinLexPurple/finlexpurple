"""Construct the configured LLM provider."""

from __future__ import annotations

from collections.abc import Callable

from finlexpurple.config import Config
from finlexpurple.config import LLMProvider as ProviderName
from finlexpurple.providers.anthropic_provider import AnthropicProvider
from finlexpurple.providers.base import LLMProvider, UnsupportedProviderError
from finlexpurple.providers.gemini_provider import GeminiProvider
from finlexpurple.providers.ollama_provider import OllamaProvider
from finlexpurple.providers.openai_provider import OpenAIProvider
from finlexpurple.providers.openrouter_provider import OpenRouterProvider

_PROVIDER_TYPES: dict[ProviderName, Callable[[Config], LLMProvider]] = {
    ProviderName.OLLAMA: OllamaProvider,
    ProviderName.ANTHROPIC: AnthropicProvider,
    ProviderName.OPENAI: OpenAIProvider,
    ProviderName.OPENROUTER: OpenRouterProvider,
    ProviderName.GEMINI: GeminiProvider,
}


def create_provider(config: Config | None = None) -> LLMProvider:
    """Create a provider using the supplied config or validated local settings."""

    active_config = config or Config.load()
    provider_name = active_config.llm_provider
    try:
        provider_type = _PROVIDER_TYPES[provider_name]
    except (KeyError, TypeError):
        raise UnsupportedProviderError(
            f"Unsupported LLM_PROVIDER value {provider_name!r}; choose one of: "
            + ", ".join(provider.value for provider in ProviderName)
        ) from None
    return provider_type(active_config)
