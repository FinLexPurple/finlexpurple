"""Phase 18: the roster and the dependency-checking invoker."""

from __future__ import annotations

from finlexpurple.agents import invoker
from finlexpurple.agents.registry import get_agent, registered_agents

_EXPECTED = {"scout", "marshal", "hunter", "sentinel", "warden", "forge", "herald", "mcp"}


def test_roster_has_every_stage_agent() -> None:
    stage = {a.name for a in registered_agents() if a.family == "stage"}
    assert stage == _EXPECTED  # the eight stage agents
    financial = {a.name for a in registered_agents() if a.family == "financial"}
    assert {"compass", "cashier", "teller"} <= financial  # Phase 19a registered too
    for a in registered_agents():
        assert a.role and a.stage and a.phase  # accurate, non-empty descriptions


def test_get_agent_is_case_insensitive_and_none_for_unknown() -> None:
    assert get_agent("HUNTER").name == "hunter"
    assert get_agent("nope") is None


def test_directly_invocable_agents() -> None:
    assert get_agent("hunter").directly_invocable is True
    assert get_agent("scout").directly_invocable is True
    assert get_agent("marshal").directly_invocable is False  # the full pipeline


def test_sentinel_without_findings_explains_cleanly() -> None:
    reason = invoker.unavailable_reason(get_agent("sentinel"), {"target"})
    assert reason is not None
    assert "findings" in reason
    assert "hunter" in reason or "scan" in reason  # tells the user how to get findings


def test_marshal_explains_it_runs_in_the_pipeline() -> None:
    reason = invoker.unavailable_reason(get_agent("marshal"), {"target"})
    assert reason is not None and "scan" in reason


def test_hunter_with_a_target_is_runnable() -> None:
    assert invoker.unavailable_reason(get_agent("hunter"), {"target"}) is None


def test_missing_requirements() -> None:
    assert invoker.missing_requirements(get_agent("forge"), {"target"}) == ["source", "findings"]
