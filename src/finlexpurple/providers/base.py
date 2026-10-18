"""Shared provider contract, response types, and normalized exceptions."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Literal, NoReturn, TypeVar

from pydantic import BaseModel, ValidationError

MessageRole = Literal["system", "user", "assistant"]
SchemaT = TypeVar("SchemaT", bound=BaseModel)


class Message(BaseModel):
    """A provider-independent conversational message."""

    role: MessageRole
    content: str


class Usage(BaseModel):
    """Token counts when the underlying API reports them."""

    input_tokens: int | None = None
    output_tokens: int | None = None


class LLMResponse(BaseModel):
    """Normalized model text and, when requested, its validated structure."""

    content: str
    model: str
    structured: BaseModel | None = None
    usage: Usage | None = None


class ProviderError(RuntimeError):
    """Base class for failures normalized across model providers."""


class MissingAPIKeyError(ProviderError):
    """A cloud provider was selected without its API key."""


class InvalidAPIKeyError(ProviderError):
    """The selected provider rejected its configured API key."""


class RateLimitError(ProviderError):
    """The provider rejected the request because of a rate or quota limit."""


class ProviderNetworkError(ProviderError):
    """The provider could not be reached or returned a server failure."""


class InvalidModelOutputError(ProviderError):
    """The model returned empty text or data that failed schema validation."""


class MissingModelError(ProviderError):
    """A model name required by the selected provider is not configured."""


class LLMProvider(ABC):
    """Provider-independent completion interface used by later phases."""

    @abstractmethod
    def complete(
        self,
        messages: list[Message],
        *,
        response_schema: type[SchemaT] | None = None,
    ) -> LLMResponse:
        """Complete messages, optionally returning data validated as a Pydantic model."""


def make_response(
    content: str,
    model: str,
    response_schema: type[SchemaT] | None,
    input_tokens: int | None = None,
    output_tokens: int | None = None,
) -> LLMResponse:
    """Build a normalized response and validate structured model output."""

    if not content.strip():
        raise InvalidModelOutputError("The model returned empty output.")
    structured: BaseModel | None = None
    if response_schema is not None:
        try:
            structured = response_schema.model_validate_json(content)
        except ValidationError:
            raise InvalidModelOutputError(
                "The model returned output that does not match the requested schema."
            ) from None
    usage = None
    if input_tokens is not None or output_tokens is not None:
        usage = Usage(input_tokens=input_tokens, output_tokens=output_tokens)
    return LLMResponse(content=content, model=model, structured=structured, usage=usage)


def raise_normalized_error(provider: str, exc: Exception) -> NoReturn:
    """Translate common SDK exception names and status codes without echoing secrets."""

    error_name = type(exc).__name__.lower()
    status = getattr(exc, "status_code", None)
    if "authentication" in error_name or status in (401, 403):
        raise InvalidAPIKeyError(f"{provider} rejected the configured API key.") from None
    if "ratelimit" in error_name or status == 429:
        raise RateLimitError(f"{provider} rate limit or quota was reached.") from None
    if (
        any(marker in error_name for marker in ("connection", "timeout", "network"))
        or isinstance(status, int)
        and status >= 500
    ):
        raise ProviderNetworkError(f"Could not complete the request to {provider}.") from None
    if isinstance(status, int):
        raise ProviderError(f"{provider} returned an API error (HTTP {status}).") from None
    raise ProviderError(f"{provider} request failed.") from None
