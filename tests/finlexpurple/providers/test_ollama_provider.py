"""Tests for the Ollama adapter using a fake local client."""

from __future__ import annotations

from types import SimpleNamespace

import httpx
import pytest
from pydantic import BaseModel, ConfigDict

from finlexpurple.config import Config
from finlexpurple.providers.base import (
    InvalidModelOutputError,
    LLMResponse,
    Message,
    MissingModelError,
    ProviderNetworkError,
)
from finlexpurple.providers.ollama_provider import OllamaProvider


class Result(BaseModel):
    model_config = ConfigDict(extra="forbid")
    value: int


def config(**overrides) -> Config:
    values = {"ollama_model": "local-test-model", "ollama_host": "http://localhost:11434"}
    values.update(overrides)
    return Config.model_construct(**values)


class FakeOllama:
    def __init__(self, contents: list[str] | None = None, error: Exception | None = None) -> None:
        self.contents = contents or ['{"value": 7}']
        self.error = error
        self.calls: list[dict] = []

    def chat(self, **params):
        self.calls.append(params)
        if self.error:
            raise self.error
        content = self.contents[min(len(self.calls) - 1, len(self.contents) - 1)]
        return SimpleNamespace(
            model="local-test-model",
            message=SimpleNamespace(content=content),
            prompt_eval_count=5,
            eval_count=3,
        )


def test_ollama_validates_schema_and_retries_invalid_json() -> None:
    client = FakeOllama(contents=["not-json", '{"value": 7}'])
    provider = OllamaProvider(config(), client=client)

    result = provider.complete(
        [Message(role="user", content="return JSON")], response_schema=Result
    )

    assert isinstance(result, LLMResponse)
    assert result.structured == Result(value=7)
    assert len(client.calls) == 2
    assert client.calls[0]["format"] == Result.model_json_schema()
    assert "did not match" in client.calls[1]["messages"][-1]["content"]


def test_ollama_reports_invalid_output_after_retry() -> None:
    client = FakeOllama(contents=["invalid", "still invalid"])
    provider = OllamaProvider(config(), client=client)

    with pytest.raises(InvalidModelOutputError):
        provider.complete([Message(role="user", content="return JSON")], response_schema=Result)

    assert len(client.calls) == 2


def test_ollama_plain_text_does_not_retry() -> None:
    client = FakeOllama(contents=["plain answer", "unused"])
    provider = OllamaProvider(config(), client=client)

    response = provider.complete([Message(role="user", content="hello")])

    assert response.content == "plain answer"
    assert len(client.calls) == 1


def test_ollama_requires_a_configured_model() -> None:
    with pytest.raises(MissingModelError, match="OLLAMA_MODEL"):
        OllamaProvider(config(ollama_model=None), client=object())


def test_ollama_connection_failure_is_typed() -> None:
    client = FakeOllama(error=httpx.ConnectError("local server unavailable"))
    provider = OllamaProvider(config(), client=client)

    with pytest.raises(ProviderNetworkError) as error:
        provider.complete([Message(role="user", content="hello")])

    assert "local server unavailable" not in str(error.value)
