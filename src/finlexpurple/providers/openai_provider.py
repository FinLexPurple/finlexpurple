"""OpenAI Chat Completions adapter and shared OpenAI-compatible implementation."""

from __future__ import annotations

from typing import Any

from openai import APIError, OpenAI
from openai.types.chat import ChatCompletionMessageParam

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


class OpenAICompatibleProvider(LLMProvider):
    """Common implementation for OpenAI and OpenAI-compatible services."""

    def __init__(
        self,
        config: Config,
        client: Any | None = None,
        *,
        api_key: str | None,
        model: str,
        provider_name: str,
        base_url: str | None = None,
    ) -> None:
        normalized_key = (api_key or "").strip()
        if not normalized_key:
            raise MissingAPIKeyError(f"{provider_name.upper()}_API_KEY is required for {provider_name}.")
        self.model = model
        self.provider_name = provider_name
        if client is None:
            client = OpenAI(api_key=normalized_key, base_url=base_url)
        self._client = client

    def complete(
        self,
        messages: list[Message],
        *,
        response_schema: type[SchemaT] | None = None,
    ) -> LLMResponse:
        request_messages: list[ChatCompletionMessageParam] = [
            _openai_message(message) for message in messages
        ]
        try:
            if response_schema is None:
                response = self._client.chat.completions.create(
                    model=self.model,
                    messages=request_messages,
                )
            else:
                response = self._client.chat.completions.parse(
                    model=self.model,
                    messages=request_messages,
                    response_format=response_schema,
                )
        except APIError as exc:
            raise_normalized_error(self.provider_name, exc)

        choice = response.choices[0]
        message = choice.message
        content = message.content or ""
        parsed = getattr(message, "parsed", None)
        if not content and parsed is not None:
            content = parsed.model_dump_json()
        usage = getattr(response, "usage", None)
        return make_response(
            content,
            self.model,
            response_schema,
            getattr(usage, "prompt_tokens", None),
            getattr(usage, "completion_tokens", None),
        )


def _openai_message(message: Message) -> ChatCompletionMessageParam:
    if message.role == "system":
        return {"role": "system", "content": message.content}
    if message.role == "user":
        return {"role": "user", "content": message.content}
    return {"role": "assistant", "content": message.content}


class OpenAIProvider(OpenAICompatibleProvider):
    """Completion adapter for OpenAI's Chat Completions API."""

    def __init__(self, config: Config, client: Any | None = None) -> None:
        super().__init__(
            config,
            client,
            api_key=config.openai_api_key,
            model=config.openai_model,
            provider_name="OpenAI",
        )
