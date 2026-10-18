"""Ollama local chat adapter with post-validation retries for structured output."""

from __future__ import annotations

from typing import Any

import httpx
from ollama import Client, ResponseError
from ollama import RequestError as OllamaRequestError

from finlexpurple.config import Config
from finlexpurple.providers.base import (
    InvalidModelOutputError,
    LLMProvider,
    LLMResponse,
    Message,
    MissingModelError,
    ProviderNetworkError,
    SchemaT,
    make_response,
    raise_normalized_error,
)

_STRUCTURED_MAX_ATTEMPTS = 2


class OllamaProvider(LLMProvider):
    """Completion adapter for a local Ollama server; no API key is used."""

    def __init__(self, config: Config, client: Any | None = None) -> None:
        self.model = (config.ollama_model or "").strip()
        if not self.model:
            raise MissingModelError("OLLAMA_MODEL must name a model installed in Ollama.")
        if client is None:
            client = Client(host=config.ollama_host)
        self._client = client

    def complete(
        self,
        messages: list[Message],
        *,
        response_schema: type[SchemaT] | None = None,
    ) -> LLMResponse:
        request_messages = [message.model_dump() for message in messages]
        max_attempts = _STRUCTURED_MAX_ATTEMPTS if response_schema is not None else 1
        last_invalid_output: InvalidModelOutputError | None = None

        for attempt in range(max_attempts):
            attempt_messages = list(request_messages)
            if attempt:
                attempt_messages.append(
                    {
                        "role": "user",
                        "content": (
                            "Your previous response did not match the required JSON schema. "
                            "Return only a corrected JSON object matching that schema."
                        ),
                    }
                )
            try:
                response = self._client.chat(
                    model=self.model,
                    messages=attempt_messages,
                    stream=False,
                    format=response_schema.model_json_schema() if response_schema else None,
                )
            except ResponseError as exc:
                raise_normalized_error("Ollama", exc)
            except (ConnectionError, OllamaRequestError, httpx.RequestError):
                raise ProviderNetworkError("Could not connect to the local Ollama server.") from None

            text = getattr(response.message, "content", "")
            usage = make_usage_counts(response)
            try:
                return make_response(
                    text,
                    getattr(response, "model", self.model),
                    response_schema,
                    usage[0],
                    usage[1],
                )
            except InvalidModelOutputError as exc:
                last_invalid_output = exc

        assert last_invalid_output is not None
        raise last_invalid_output


def make_usage_counts(response: Any) -> tuple[int | None, int | None]:
    """Extract Ollama's optional prompt and completion token counts."""

    return (
        getattr(response, "prompt_eval_count", None),
        getattr(response, "eval_count", None),
    )
