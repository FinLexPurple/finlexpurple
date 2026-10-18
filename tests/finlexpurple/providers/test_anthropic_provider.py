"""Tests for the Anthropic adapter using a fake client."""

from __future__ import annotations

from types import SimpleNamespace

import anthropic
import pytest
from pydantic import BaseModel, ConfigDict

from finlexpurple.config import Config
from finlexpurple.providers.anthropic_provider import AnthropicProvider
from finlexpurple.providers.base import InvalidAPIKeyError, Message, MissingAPIKeyError


class Result(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value: int


def config(**overrides) -> Config:
    values = {
        "anthropic_api_key": "test-anthropic-secret",
        "anthropic_model": "test-claude-model",
    }
    values.update(overrides)
    return Config.model_construct(**values)


class FakeMessages:
    def __init__(self, response=None, error: Exception | None = None) -> None:
        self.response = response or SimpleNamespace(
            content=[SimpleNamespace(type="text", text='{"value": 7}')],
            model="test-claude-model",
            usage=SimpleNamespace(input_tokens=5, output_tokens=3),
        )
        self.error = error
        self.params = None

    def create(self, **params):
        self.params = params
        if self.error:
            raise self.error
        return self.response


def test_anthropic_plain_and_structured_completion() -> None:
    messages_api = FakeMessages()
    provider = AnthropicProvider(config(), client=SimpleNamespace(messages=messages_api))

    response = provider.complete(
        [Message(role="system", content="Be precise."), Message(role="user", content="Return JSON.")],
        response_schema=Result,
    )

    assert response.structured == Result(value=7)
    assert messages_api.params["system"] == "Be precise."
    assert messages_api.params["output_config"]["format"]["schema"] == Result.model_json_schema()


def test_anthropic_requires_key_without_echoing_it() -> None:
    with pytest.raises(MissingAPIKeyError, match="ANTHROPIC_API_KEY"):
        AnthropicProvider(config(anthropic_api_key=None), client=object())


class AuthenticationError(anthropic.APIError):
    status_code = 401

    def __init__(self, message: str) -> None:
        Exception.__init__(self, message)


def test_anthropic_invalid_key_is_typed_and_sanitized() -> None:
    client = SimpleNamespace(messages=FakeMessages(error=AuthenticationError("secret")))
    provider = AnthropicProvider(config(), client=client)

    with pytest.raises(InvalidAPIKeyError) as error:
        provider.complete([Message(role="user", content="hello")])

    assert "secret" not in str(error.value)
