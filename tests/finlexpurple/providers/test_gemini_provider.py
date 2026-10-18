"""Tests for the Gemini adapter using a fake client."""

from __future__ import annotations

from types import SimpleNamespace

import pytest
from google.genai.errors import APIError
from pydantic import BaseModel

from finlexpurple.config import Config
from finlexpurple.providers.base import InvalidAPIKeyError, Message, MissingAPIKeyError
from finlexpurple.providers.gemini_provider import GeminiProvider


class Result(BaseModel):
    value: int


def config(**overrides) -> Config:
    values = {"gemini_api_key": "test-gemini-secret", "gemini_model": "test-gemini-model"}
    values.update(overrides)
    return Config.model_construct(**values)


class FakeModels:
    def __init__(self, error: Exception | None = None) -> None:
        self.error = error
        self.params = None

    def generate_content(self, **params):
        self.params = params
        if self.error:
            raise self.error
        return SimpleNamespace(
            text='{"value": 7}',
            usage_metadata=SimpleNamespace(prompt_token_count=5, candidates_token_count=3),
        )


def test_gemini_plain_and_structured_completion() -> None:
    models = FakeModels()
    provider = GeminiProvider(config(), client=SimpleNamespace(models=models))

    result = provider.complete(
        [Message(role="system", content="Be precise."), Message(role="user", content="return JSON")],
        response_schema=Result,
    )

    assert result.structured == Result(value=7)
    assert models.params["config"].system_instruction == "Be precise."
    assert models.params["config"].response_schema is Result


def test_gemini_requires_key() -> None:
    with pytest.raises(MissingAPIKeyError, match="GEMINI_API_KEY"):
        GeminiProvider(config(gemini_api_key=None), client=object())


def test_gemini_invalid_key_is_typed_and_sanitized() -> None:
    models = FakeModels(error=APIError(code=401, response_json={"message": "secret"}))
    provider = GeminiProvider(config(), client=SimpleNamespace(models=models))

    with pytest.raises(InvalidAPIKeyError) as error:
        provider.complete([Message(role="user", content="hello")])

    assert "secret" not in str(error.value)
