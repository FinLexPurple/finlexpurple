"""Tests for structured output and secret redaction."""

from __future__ import annotations

import io
import json
import logging
from types import SimpleNamespace

import openai
import pytest

from finlexpurple.config import Config
from finlexpurple.logging_setup import HumanFormatter, JsonFormatter, RedactionFilter
from finlexpurple.providers.base import InvalidAPIKeyError, Message
from finlexpurple.providers.openai_provider import OpenAIProvider


@pytest.mark.parametrize("formatter", [HumanFormatter("%(levelname)s %(message)s"), JsonFormatter()])
def test_redacts_secret_fields_and_assignments(
    formatter: logging.Formatter, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "sk-environment-value")
    output = io.StringIO()
    handler = logging.StreamHandler(output)
    handler.addFilter(RedactionFilter())
    handler.setFormatter(formatter)
    logger = logging.getLogger("test-redaction")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()
    logger.propagate = False
    logger.addHandler(handler)

    for level in (logging.DEBUG, logging.INFO, logging.WARNING, logging.ERROR, logging.CRITICAL):
        logger.log(
            level,
            "configured OPENAI_API_KEY=sk-inline; raw secret value: %s",
            "sk-environment-value",
            extra={"authorization_token": "bearer-inline"},
        )
    rendered = output.getvalue()

    assert "sk-inline" not in rendered
    assert "bearer-inline" not in rendered
    assert "sk-environment-value" not in rendered
    assert "[REDACTED]" in rendered
    if isinstance(formatter, JsonFormatter):
        entries = [json.loads(line) for line in rendered.splitlines()]
        assert [entry["level"] for entry in entries] == [
            "DEBUG",
            "INFO",
            "WARNING",
            "ERROR",
            "CRITICAL",
        ]


@pytest.mark.parametrize("formatter", [HumanFormatter("%(levelname)s %(message)s"), JsonFormatter()])
def test_redacts_all_http_query_values_in_messages_and_arguments(
    formatter: logging.Formatter,
) -> None:
    output = io.StringIO()
    handler = logging.StreamHandler(output)
    handler.addFilter(RedactionFilter())
    handler.setFormatter(formatter)
    logger = logging.getLogger(f"test-query-redaction-{type(formatter).__name__}")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    logger.propagate = False
    logger.addHandler(handler)

    logger.info("Request URL: %s", "https://example.test/search?q=private&access_token=token-value")

    rendered = output.getvalue()
    assert "private" not in rendered
    assert "token-value" not in rendered
    assert "q=[REDACTED]" in rendered
    assert "access_token=[REDACTED]" in rendered


class FakeAuthenticationError(openai.APIError):
    status_code = 401

    def __init__(self, message: str) -> None:
        Exception.__init__(self, message)


class RecordCapture(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.addFilter(RedactionFilter())
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


def test_provider_secret_never_appears_in_exception_output_or_json_logs(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    fake_key = "sk-fake-secret-that-must-not-appear"
    monkeypatch.setenv("OPENAI_API_KEY", fake_key)
    failure = FakeAuthenticationError(f"rejected credential {fake_key}")
    completions = SimpleNamespace(create=lambda **_: (_ for _ in ()).throw(failure))
    client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    provider = OpenAIProvider(
        Config.model_construct(
            openai_api_key=fake_key,
            openai_model="test-model",
        ),
        client=client,
    )

    output = io.StringIO()
    json_handler = logging.StreamHandler(output)
    json_handler.addFilter(RedactionFilter())
    json_handler.setFormatter(JsonFormatter())
    record_capture = RecordCapture()
    logger = logging.getLogger("test-provider-secret-redaction")
    previous_handlers = logger.handlers[:]
    previous_level = logger.level
    previous_propagate = logger.propagate
    logger.handlers.clear()
    logger.setLevel(logging.ERROR)
    logger.propagate = False
    logger.addHandler(json_handler)
    logger.addHandler(record_capture)
    try:
        with pytest.raises(InvalidAPIKeyError) as caught:
            provider.complete([Message(role="user", content="hello")])
        print(caught.value)
        logger.error("Provider failed: %s", caught.value, extra={"provider_api_key": fake_key})
    finally:
        logger.handlers.clear()
        for handler in previous_handlers:
            logger.addHandler(handler)
        logger.setLevel(previous_level)
        logger.propagate = previous_propagate

    rendered_output = capsys.readouterr().out
    rendered_json = output.getvalue()
    assert fake_key not in str(caught.value)
    assert fake_key not in repr(caught.value.args)
    assert fake_key not in rendered_output
    assert fake_key not in rendered_json
    assert record_capture.records
    assert all(fake_key not in record.getMessage() for record in record_capture.records)
    assert all(fake_key not in repr(record.__dict__) for record in record_capture.records)
