"""Google Gemini Generate Content API adapter."""

from __future__ import annotations

from typing import Any

from google.genai import Client, types
from google.genai.errors import APIError

from finlexpurple.config import Config
from finlexpurple.providers.base import (
    LLMProvider,
    LLMResponse,
    Message,
    MissingAPIKeyError,
    SchemaT,
    make_response,
    raise_normalized_error,
)


class GeminiProvider(LLMProvider):
    """Completion adapter for Google's Gemini API."""

    def __init__(self, config: Config, client: Any | None = None) -> None:
        api_key = (config.gemini_api_key or "").strip()
        if not api_key:
            raise MissingAPIKeyError("GEMINI_API_KEY is required for Gemini.")
        self.model = config.gemini_model
        if client is None:
            client = Client(api_key=api_key)
        self._client = client

    def complete(
        self,
        messages: list[Message],
        *,
        response_schema: type[SchemaT] | None = None,
    ) -> LLMResponse:
        system_parts = [message.content for message in messages if message.role == "system"]
        contents = [
            {
                "role": "model" if message.role == "assistant" else "user",
                "parts": [{"text": message.content}],
            }
            for message in messages
            if message.role != "system"
        ]
        config: dict[str, Any] = {}
        if system_parts:
            config["system_instruction"] = "\n\n".join(system_parts)
        if response_schema is not None:
            config["response_mime_type"] = "application/json"
            config["response_schema"] = response_schema
        try:
            response = self._client.models.generate_content(
                model=self.model,
                contents=contents,
                config=types.GenerateContentConfig(**config) if config else None,
            )
        except APIError as exc:
            raise_normalized_error("Gemini", exc)

        usage = getattr(response, "usage_metadata", None)
        return make_response(
            getattr(response, "text", None) or "",
            self.model,
            response_schema,
            getattr(usage, "prompt_token_count", None),
            getattr(usage, "candidates_token_count", None),
        )
