"""Anthropic Messages API adapter."""

from __future__ import annotations

from typing import Any

from anthropic import Anthropic, APIError

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

_MAX_OUTPUT_TOKENS = 4096


class AnthropicProvider(LLMProvider):
    """Completion adapter for Anthropic's Claude Messages API."""

    def __init__(self, config: Config, client: Any | None = None) -> None:
        api_key = (config.anthropic_api_key or "").strip()
        if not api_key:
            raise MissingAPIKeyError("ANTHROPIC_API_KEY is required for Anthropic.")
        self.model = config.anthropic_model
        if client is None:
            client = Anthropic(api_key=api_key)
        self._client = client

    def complete(
        self,
        messages: list[Message],
        *,
        response_schema: type[SchemaT] | None = None,
    ) -> LLMResponse:
        system_parts = [message.content for message in messages if message.role == "system"]
        request_messages = [
            {"role": message.role, "content": message.content}
            for message in messages
            if message.role != "system"
        ]
        params: dict[str, Any] = {
            "model": self.model,
            "max_tokens": _MAX_OUTPUT_TOKENS,
            "messages": request_messages,
        }
        if system_parts:
            params["system"] = "\n\n".join(system_parts)
        try:
            if response_schema is None:
                response = self._client.messages.create(**params)
            else:
                response = self._client.messages.parse(
                    **params,
                    output_format=response_schema,
                )
        except APIError as exc:
            raise_normalized_error("Anthropic", exc)

        content = "".join(
            block.text for block in response.content if getattr(block, "type", None) == "text"
        )
        usage = getattr(response, "usage", None)
        return make_response(
            content,
            getattr(response, "model", self.model),
            response_schema,
            getattr(usage, "input_tokens", None),
            getattr(usage, "output_tokens", None),
        )
