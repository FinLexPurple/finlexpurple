"""Tests for the OpenAI adapter using a fake client."""

from __future__ import annotations

from types import SimpleNamespace

import openai
import pytest
from pydantic import BaseModel

from finlexpurple.config import Config
from finlexpurple.providers.base import InvalidAPIKeyError, Message, MissingAPIKeyError
from finlexpurple.providers.openai_provider import OpenAIProvider


class Result(BaseModel):
    value: int


def config(**overrides) -> Config:
    values = {"openai_api_key": "test-openai-secret", "openai_model": "test-gpt-model"}
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
        return response()

    def create(self, **params):
        self.params = params
        if self.error:
            raise self.error
        return response(content="plain answer")


def response(content: str = '{"value": 7}'):
    return SimpleNamespace(
        choices=[
            SimpleNamespace(message=SimpleNamespace(content=content, parsed=None))
        ],
        usage=SimpleNamespace(prompt_tokens=5, completion_tokens=3),
    )


def test_openai_plain_and_structured_completion() -> None:
    completions = FakeCompletions()
    provider = OpenAIProvider(
        config(), client=SimpleNamespace(chat=SimpleNamespace(completions=completions))
    )

    plain = provider.complete([Message(role="user", content="hello")])
    structured = provider.complete(
        [Message(role="user", content="return JSON")], response_schema=Result
    )

    assert plain.content == "plain answer"
    assert structured.structured == Result(value=7)
    assert completions.params["response_format"] is Result


def test_openai_requires_key() -> None:
    with pytest.raises(MissingAPIKeyError, match="OPENAI_API_KEY"):
        OpenAIProvider(config(openai_api_key=None), client=object())


class AuthenticationError(openai.APIError):
    status_code = 401

    def __init__(self, message: str) -> None:
        Exception.__init__(self, message)


def test_openai_invalid_key_is_typed_and_sanitized() -> None:
    completions = FakeCompletions(error=AuthenticationError("secret"))
    client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    provider = OpenAIProvider(config(), client=client)

    with pytest.raises(InvalidAPIKeyError) as error:
        provider.complete([Message(role="user", content="hello")])

    assert "secret" not in str(error.value)
