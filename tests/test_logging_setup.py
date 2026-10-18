"""Tests for structured output and secret redaction."""

from __future__ import annotations

import io
import json
import logging

import pytest

from finlexpurple.logging_setup import HumanFormatter, JsonFormatter, RedactionFilter


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
