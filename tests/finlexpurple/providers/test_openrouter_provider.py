"""Tests for the OpenRouter adapter using a fake compatible client."""

from __future__ import annotations

from types import SimpleNamespace

import openai
import pytest
from pydantic import BaseModel

from finlexpurple.config import Config
from finlexpurple.providers.base import InvalidAPIKeyError, Message, MissingAPIKeyError
from finlexpurple.providers.openrouter_provider import OpenRouterProvider


class Result(BaseModel):
    value: int


def config(**overrides) -> Config:
    values = {
        "openrouter_api_key": "test-openrouter-secret",
        "openrouter_model": "openai/test-model",
    }
    values.update(overrides)
    return Config.model_construct(**values)


class FakeCompletions:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.params = None

    def parse(self, **params):
        self.params = params
        if self.error:
            raise self.error
        return SimpleNamespace(
            choices=[SimpleNamespace(message=SimpleNamespace(content='{"value": 7}', parsed=None))],
            usage=None,
        )

    def create(self, **params):
        return self.parse(**params)


def test_openrouter_uses_compatible_completion_and_schema() -> None:
    completions = FakeCompletions()
    client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    provider = OpenRouterProvider(config(), client=client)

    result = provider.complete([Message(role="user", content="return JSON")], response_schema=Result)

    assert result.structured == Result(value=7)
    assert completions.params["model"] == "openai/test-model"
    assert completions.params["response_format"] is Result


def test_openrouter_requires_key() -> None:
    with pytest.raises(MissingAPIKeyError, match="OPENROUTER_API_KEY"):
        OpenRouterProvider(config(openrouter_api_key=None), client=object())


class AuthenticationError(openai.APIError):
    status_code = 401

    def __init__(self, message: str) -> None:
        Exception.__init__(self, message)


def test_openrouter_invalid_key_is_typed_and_sanitized() -> None:
    completions = FakeCompletions(error=AuthenticationError("secret"))
    client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    provider = OpenRouterProvider(config(), client=client)

    with pytest.raises(InvalidAPIKeyError) as error:
        provider.complete([Message(role="user", content="hello")])

    assert "secret" not in str(error.value)
