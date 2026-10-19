"""Redacted human-readable and JSON logging configuration."""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any
from urllib.parse import parse_qsl, urlsplit, urlunsplit

_SECRET_FIELD = re.compile(r"(?:KEY|TOKEN|SECRET)", re.IGNORECASE)
_SECRET_ASSIGNMENT = re.compile(
    r"(?i)\b([A-Z0-9_]*(?:KEY|TOKEN|SECRET)[A-Z0-9_]*)\s*([=:])\s*([^\s,;]+)"
)
_URL_PATTERN = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
_STANDARD_FIELDS = set(logging.makeLogRecord({}).__dict__) | {"message", "asctime"}


def _redact_value(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: "[REDACTED]" if _SECRET_FIELD.search(str(key)) else _redact_value(item)
            for key, item in value.items()
        }
    if isinstance(value, tuple):
        return tuple(_redact_value(item) for item in value)
    if isinstance(value, list):
        return [_redact_value(item) for item in value]
    if isinstance(value, str):
        redacted = _SECRET_ASSIGNMENT.sub(r"\1\2[REDACTED]", value)
        redacted = _URL_PATTERN.sub(_redact_url_query, redacted)
        secrets = {
            secret
            for name, secret in os.environ.items()
            if _SECRET_FIELD.search(name) and secret
        }
        for secret in sorted(secrets, key=len, reverse=True):
            redacted = redacted.replace(secret, "[REDACTED]")
        return redacted
    return value


def _redact_url_query(match: re.Match[str]) -> str:
    """Remove every value from HTTP(S) query strings found in log text."""

    raw_url = match.group(0)
    try:
        parts = urlsplit(raw_url)
        if not parts.query:
            return raw_url
        safe_query = "&".join(
            f"{key}=[REDACTED]" for key, _ in parse_qsl(parts.query, keep_blank_values=True)
        )
        return urlunsplit((parts.scheme, parts.netloc, parts.path, safe_query, ""))
    except ValueError:
        return "<redacted-url>"


class RedactionFilter(logging.Filter):
    """Redact secret-named structured fields and assignments in messages."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.msg = _redact_value(record.msg)
        record.args = _redact_value(record.args)
        for key, value in list(record.__dict__.items()):
            if key not in _STANDARD_FIELDS:
                record.__dict__[key] = "[REDACTED]" if _SECRET_FIELD.search(key) else _redact_value(value)
        return True


class HumanFormatter(logging.Formatter):
    """Compact terminal output, including structured context fields."""

    def format(self, record: logging.LogRecord) -> str:
        message = super().format(record)
        extras = {
            key: value
            for key, value in record.__dict__.items()
            if key not in _STANDARD_FIELDS and not key.startswith("_")
        }
        if extras:
            message += " " + json.dumps(_redact_value(extras), sort_keys=True, default=str)
        return message


class JsonFormatter(logging.Formatter):
    """One JSON object per emitted record."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "timestamp": datetime.fromtimestamp(record.created, timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        payload.update(
            {
                key: value
                for key, value in record.__dict__.items()
                if key not in _STANDARD_FIELDS and not key.startswith("_")
            }
        )
        return json.dumps(_redact_value(payload), sort_keys=True, default=str)


def configure_logging(json_logs: bool = False, level: int = logging.INFO) -> None:
    """Configure the root logger with secret redaction enabled."""

    handler = logging.StreamHandler()
    handler.addFilter(RedactionFilter())
    handler.setFormatter(JsonFormatter() if json_logs else HumanFormatter("%(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
