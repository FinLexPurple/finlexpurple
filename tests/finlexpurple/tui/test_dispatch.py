"""The autonomous dispatcher runs only registered ops, is bounded, and cannot invent ops."""

from __future__ import annotations

import io

from finlexpurple.providers.base import LLMResponse
from finlexpurple.tui.dispatch import ChatAction, Operation, OperationResult, dispatch_turn
from finlexpurple.tui.theme import make_console


class _FakeProvider:
    """Returns a scripted ChatAction per call (as the structured field), like a real provider."""

    def __init__(self, script: list[ChatAction]) -> None:
        self._script = script
        self.calls = 0

    def complete(self, messages, *, response_schema=None):
        action = self._script[min(self.calls, len(self._script) - 1)]
        self.calls += 1
        return LLMResponse(content=action.message or "", model="fake", structured=action)


def _console() -> object:
    return make_console(file=io.StringIO(), no_color=True, width=72)


def test_reply_only_turn_opens_no_activity_stream() -> None:
    con = _console()
    reply = dispatch_turn(provider=_FakeProvider([ChatAction(action="reply", message="hello")]),
                          console=con, system_prompt="s", user_input="hi", history=[])
    assert reply == "hello"
    assert con.file.getvalue() == ""  # no stream for a pure reply


def test_agent_runs_a_registered_operation_then_replies() -> None:
    con = _console()
    provider = _FakeProvider([ChatAction(action="list_agents"), ChatAction(action="reply", message="done")])
    reply = dispatch_turn(provider=provider, console=con, system_prompt="s",
                          user_input="list agents", history=[])
    assert reply == "done"
    assert "list agents" in con.file.getvalue()  # the activity card rendered


def test_custom_operation_result_feeds_back_and_renders() -> None:
    ran: list[bool] = []

    def op() -> OperationResult:
        ran.append(True)
        return OperationResult(summary="ok", text="DETAIL-123")

    ops = {"list_agents": Operation(label="my op", run=op)}
    con = _console()
    provider = _FakeProvider([ChatAction(action="list_agents"), ChatAction(action="reply", message="fin")])
    reply = dispatch_turn(provider=provider, console=con, system_prompt="s", user_input="go",
                          history=[], operations=ops)
    assert ran == [True] and reply == "fin"
    assert "my op" in con.file.getvalue() and "ok" in con.file.getvalue()


def test_unregistered_action_is_refused_not_invented() -> None:
    # A decision for an action not in the registry is refused (the model cannot invent ops).
    bogus = ChatAction(action="list_agents")
    object.__setattr__(bogus, "action", "delete_everything")  # force an off-registry action
    con = _console()
    reply = dispatch_turn(provider=_FakeProvider([bogus]), console=con, system_prompt="s",
                          user_input="x", history=[], operations={})
    assert "unavailable operation" in reply


def test_turn_is_bounded_by_the_op_cap() -> None:
    # The model keeps choosing an operation; the dispatcher stops after max_ops and replies.
    con = _console()
    provider = _FakeProvider([ChatAction(action="list_agents")])  # always an op
    reply = dispatch_turn(provider=provider, console=con, system_prompt="s", user_input="loop",
                          history=[], max_ops=3)
    # 3 operation decisions + 1 forced final reply call == 4 provider calls, then it stops.
    assert provider.calls == 4
    assert isinstance(reply, str)
