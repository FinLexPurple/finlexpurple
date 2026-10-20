"""Phase 14: hadolint output parsed from real JSON, not paraphrased."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from finlexpurple.container.hadolint_wrapper import (
    HadolintError,
    parse_hadolint_output,
    run_hadolint,
)
from finlexpurple.detectors.schema import Severity

_HADOLINT_JSON = json.dumps(
    [
        {"line": 3, "code": "DL3008", "message": "Pin versions in apt get install",
         "level": "warning", "column": 1, "file": "Dockerfile"},
        {"line": 1, "code": "DL3006", "message": "Always tag the version of an image",
         "level": "error", "column": 1, "file": "Dockerfile"},
    ]
)


def test_parse_normalizes_list_and_maps_levels() -> None:
    findings = parse_hadolint_output(_HADOLINT_JSON)
    assert len(findings) == 2
    by_code = {f.payload.split(":", 1)[0]: f.severity for f in findings}
    assert by_code["DL3006"] is Severity.HIGH  # error
    assert by_code["DL3008"] is Severity.MEDIUM  # warning


def test_snapshot_is_verbatim_message() -> None:
    f = parse_hadolint_output(_HADOLINT_JSON)[0]
    snap = json.loads(f.response_snapshot or "{}")
    assert snap["code"] in {"DL3008", "DL3006"}


def test_empty_invalid_and_run() -> None:
    assert parse_hadolint_output("") == []
    with pytest.raises(HadolintError):
        parse_hadolint_output(json.dumps({"not": "a list"}))
    assert len(run_hadolint(Path("Dockerfile"), runner=lambda args: (1, _HADOLINT_JSON, ""))) == 2
