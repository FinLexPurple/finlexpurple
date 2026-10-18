"""OpenRouter adapter using its OpenAI-compatible API endpoint."""

from __future__ import annotations

from typing import Any

from finlexpurple.config import Config
from finlexpurple.providers.openai_provider import OpenAICompatibleProvider

_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"


class OpenRouterProvider(OpenAICompatibleProvider):
    """Completion adapter for OpenRouter's OpenAI-compatible chat API."""

    def __init__(self, config: Config, client: Any | None = None) -> None:
        super().__init__(
            config,
            client,
            api_key=config.openrouter_api_key,
            model=config.openrouter_model,
            provider_name="OpenRouter",
            base_url=_OPENROUTER_BASE_URL,
        )
