"""Tests for the provider-independent contract and error translation."""

from __future__ import annotations

import pytest
from pydantic import BaseModel

from finlexpurple.providers.base import (
    InvalidAPIKeyError,
    InvalidModelOutputError,
    Message,
    ProviderNetworkError,
    RateLimitError,
    make_response,
    raise_normalized_error,
)


class Answer(BaseModel):
    answer: int


def test_message_and_structured_response_are_normalized() -> None:
    message = Message(role="user", content="Return an answer.")
    response = make_response('{"answer": 42}', "test-model", Answer, 3, 2)

    assert message.role == "user"
    assert response.structured == Answer(answer=42)
    assert response.usage is not None
    assert response.usage.input_tokens == 3
    assert response.usage.output_tokens == 2


@pytest.mark.parametrize("content", ["", "   ", "not-json", '{"answer":"wrong"}'])
def test_invalid_structured_output_is_typed(content: str) -> None:
    with pytest.raises(InvalidModelOutputError):
        make_response(content, "test-model", Answer)


class AuthenticationError(Exception):
    pass


class RateLimitErrorFromSdk(Exception):
    pass


class APIConnectionError(Exception):
    pass


@pytest.mark.parametrize(
    ("error", "expected"),
    [
        (AuthenticationError("secret must not leak"), InvalidAPIKeyError),
        (RateLimitErrorFromSdk("limited"), RateLimitError),
        (APIConnectionError("offline"), ProviderNetworkError),
    ],
)
def test_sdk_errors_are_normalized_without_echoing_secrets(error, expected) -> None:
    with pytest.raises(expected) as caught:
        raise_normalized_error("Example", error)

    assert "secret" not in str(caught.value)
