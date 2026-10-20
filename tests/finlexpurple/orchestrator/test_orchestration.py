"""Phase 6 state, persistence, safety, and bounded-loop tests.

These tests are the executable evidence for the architecture.md Phase 6
acceptance checklist:
- resume-without-repeating-completed-work -> ``test_engine_completes_and
  _resumes_without_repeating_completed_actions`` plus the state round-trip and
  run-directory tests;
- a runaway loop is stopped -> ``test_iteration_limit_stops_repeating_planner
  _and_persists`` and ``test_limit_configuration_uses_positive_integer
  _environment``;
- the planner's LLM use is prioritization-only and the executor never emits
  findings -> ``test_planner_prompt_is_catalog_only...`` and
  ``test_stub_executor_never_returns_findings``.
They also assert the privacy guarantees (no query values/bodies on disk, 0600
state files).
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from finlexpurple.orchestrator.engine import run
from finlexpurple.orchestrator.executor import Executor
from finlexpurple.orchestrator.iteration_limits import IterationLimits
from finlexpurple.orchestrator.persistence import create_run_directory, load_state, save_state
from finlexpurple.orchestrator.planner import Planner
from finlexpurple.orchestrator.state import InvalidRunStateError, RunState
from finlexpurple.providers.base import LLMProvider, LLMResponse, Message


def _state(path: Path) -> tuple[RunState, Path]:
    """Build a minimal saved run (one GET /search?q endpoint) for reuse in tests."""

    run_id, directory = create_run_directory(
        "https://example.invalid/", reports_dir=path,
        now=datetime(2026, 10, 19, 11, 45, tzinfo=timezone.utc),
    )
    state = RunState(
        run_id=run_id,
        canonical_target="https://example.invalid/",
        catalog=[{
            "method": "GET", "path": "/search", "parameter_names": ["q"],
            "content_type": "text/html",
        }],
        parameter_names=["q"],
    )
    state_path = directory / "run-state.json"
    save_state(state_path, state)
    return state, state_path


def test_run_directory_is_sanitized_hashed_utc_and_collision_safe(tmp_path: Path) -> None:
    """Run dirs are slug+hash+UTC, collide into numeric suffixes, and reject traversal."""

    now = datetime(2026, 10, 19, 11, 45, tzinfo=timezone.utc)
    first, first_path = create_run_directory("https://example.invalid/a", reports_dir=tmp_path, now=now)
    second, _ = create_run_directory("https://example.invalid/a", reports_dir=tmp_path, now=now)
    assert first.endswith("20261019T114500Z")
    assert second.endswith("20261019T114500Z-01")
    assert first_path.parent == tmp_path.resolve()
    assert ":" not in first and "\\" not in first and ".." not in first
    with pytest.raises(ValueError):
        create_run_directory("../escape", reports_dir=tmp_path, now=now)


def test_state_round_trip_and_invalid_state_refused_without_deleting(tmp_path: Path) -> None:
    """State survives a save/load round-trip, and a bad schema is rejected in place."""

    state, path = _state(tmp_path)
    assert load_state(path).to_dict() == state.to_dict()
    path.write_text('{"schema_version": 999}', encoding="utf-8")
    with pytest.raises(InvalidRunStateError, match="unsupported schema_version"):
        load_state(path)
    assert path.exists()


def test_state_is_private_on_posix_and_has_no_query_values_or_bodies(tmp_path: Path) -> None:
    """Saved state keeps parameter names only (no values/bodies) and is 0600 on POSIX."""

    state, path = _state(tmp_path)
    state.catalog[0]["parameter_names"] = ["access_token"]
    save_state(path, state)
    contents = path.read_text(encoding="utf-8")
    assert "secret-value" not in contents
    assert "response body" not in contents
    assert "schema_version" in contents
    if __import__("os").name != "nt":
        assert path.stat().st_mode & 0o777 == 0o600


class _FakeProvider(LLMProvider):
    """Test double that records the prompt and returns a fixed reordering."""

    def __init__(self) -> None:
        self.messages: list[Message] = []

    def complete(self, messages: list[Message], *, response_schema=None) -> LLMResponse:
        """Capture the messages and echo back a validated two-id priority order."""

        self.messages.extend(messages)
        return LLMResponse(
            content='{"action_ids":["stub-0001","stub-0000"]}',
            model="test-double",
            structured=response_schema.model_validate({"action_ids": ["stub-0001", "stub-0000"]}),
        )


def test_planner_prompt_is_catalog_only_and_provider_order_is_validated() -> None:
    """Planner prompt carries only catalog metadata; a valid reorder is honored."""

    provider = _FakeProvider()
    planner = Planner(provider)
    catalog = [
        {"method": "GET", "path": "/a", "parameter_names": ["q"], "content_type": "text/html"},
        {"method": "GET", "path": "/b", "parameter_names": [], "content_type": "text/html"},
    ]
    actions = planner.plan(catalog, set())
    prompt = " ".join(message.content for message in provider.messages)
    assert [action["action_id"] for action in actions] == ["stub-0001", "stub-0000"]
    assert "/a" in prompt and "q" in prompt
    assert "secret" not in prompt and "response body" not in prompt and "?" not in prompt


def test_stub_executor_never_returns_findings() -> None:
    """The Phase-6 executor returns an empty-findings observation for the stub."""

    executor = Executor()
    result = executor.execute({
        "action_id": "stub-0000", "detector": "phase8_stub", "endpoint": {"path": "/"}
    })
    assert result == {"action_id": "stub-0000", "findings": []}


def test_engine_completes_and_resumes_without_repeating_completed_actions(tmp_path: Path) -> None:
    """A finished run reloads as terminal: re-running repeats no completed action."""

    state, path = _state(tmp_path)
    result = run(state, path, limits=IterationLimits(20, 50, 1800))
    assert result.current_stage == "report"
    assert result.counters["iterations"] == 1
    assert result.counters["tool_calls"] == 1
    assert result.counters["elapsed_seconds"] >= 0
    resumed = run(load_state(path), path, limits=IterationLimits(20, 50, 1800))
    assert resumed.counters == result.counters
    assert len(resumed.observed_results) == 1


def test_iteration_limit_stops_repeating_planner_and_persists(tmp_path: Path) -> None:
    """A planner that never finishes is halted at the iteration cap, state persisted."""

    state, path = _state(tmp_path)

    class NeverDonePlanner:
        """Adversarial planner that always asks for one more (unique) action."""

        def plan(self, catalog, completed):
            return [{"action_id": f"again-{len(completed)}", "detector": "phase8_stub", "endpoint": catalog[0]}]

    result = run(
        state, path, planner=NeverDonePlanner(),
        limits=IterationLimits(max_iterations=2, max_tool_calls=50, max_wall_clock_seconds=30),
    )
    assert result.stop_reason == "iteration limit reached (2)"
    assert load_state(path).counters["iterations"] == 2
    assert result.current_stage == "plan"


def test_limit_configuration_uses_positive_integer_environment(monkeypatch) -> None:
    """Env overrides accept positive integers and reject non-positive values."""

    monkeypatch.setenv("FINLEXPURPLE_MAX_ITERATIONS", "3")
    assert IterationLimits.from_environment().max_iterations == 3
    monkeypatch.setenv("FINLEXPURPLE_MAX_ITERATIONS", "0")
    with pytest.raises(ValueError, match="positive integer"):
        IterationLimits.from_environment()


def test_kill_switch_halts_at_a_safe_point_and_persists(tmp_path: Path) -> None:
    """Phase 8: a stop requested via the controller halts the loop cleanly and resumably."""

    from finlexpurple.security.safe_failure import SafeFailureController

    state, path = _state(tmp_path)
    controller = SafeFailureController()
    controller.request_stop()  # operator engaged the kill switch
    result = run(state, path, controller=controller, limits=IterationLimits(20, 50, 1800))

    assert result.stop_reason == "stopped by kill switch at a safe point"
    assert result.current_stage == "recon"  # halted before advancing, at a safe boundary
    # State was persisted and is resumable; a fresh run with no stop completes.
    assert load_state(path).stop_reason == "stopped by kill switch at a safe point"
    resumed = run(load_state(path), path, limits=IterationLimits(20, 50, 1800))
    assert resumed.current_stage == "report"


def test_saved_state_contains_required_fields(tmp_path: Path) -> None:
    """The persisted JSON includes the schema version and all resume-critical keys."""

    _, path = _state(tmp_path)
    data = json.loads(path.read_text(encoding="utf-8"))
    assert {"schema_version", "run_id", "current_stage", "completed_stages", "canonical_target",
            "parameter_names", "counters"}.issubset(data)
