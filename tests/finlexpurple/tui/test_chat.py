"""The chat REPL loop handles turns, slash-commands, and exits; the CLI guards interactivity."""

from __future__ import annotations

import io

from prompt_toolkit import PromptSession
from prompt_toolkit.input import create_pipe_input
from prompt_toolkit.output import DummyOutput
from typer.testing import CliRunner

from finlexpurple.cli import app
from finlexpurple.providers.base import Message
from finlexpurple.tui.chat import run_chat
from finlexpurple.tui.components import SessionInfo
from finlexpurple.tui.theme import make_console


def _run(script: str, handler) -> str:
    console = make_console(file=io.StringIO(), no_color=True, width=72)
    with create_pipe_input() as pipe:
        pipe.send_text(script)
        session = PromptSession(input=pipe, output=DummyOutput())
        code = run_chat(console=console, handler=handler, info=SessionInfo(target="http://lab.invalid"),
                        session=session, color=False)
    assert code == 0
    return console.file.getvalue()


def test_session_screen_prints_once_at_the_top() -> None:
    out = _run("/exit\n", lambda line, history: "")
    assert "█" in out         # block wordmark cells
    assert "TARGET:" in out        # session-info box
    assert "/scan" in out          # hints
    assert "Tip" in out            # tip line
    assert out.rstrip().endswith("bye")


def test_a_user_turn_is_handled_and_history_accumulates() -> None:
    seen: list[int] = []

    def handler(line: str, history: list[Message]) -> str:
        seen.append(len(history))
        return f"echo: {line}"

    out = _run("one\ntwo\n/exit\n", handler)
    assert "echo: one" in out and "echo: two" in out
    # First turn sees empty history; second sees the first turn's two messages.
    assert seen == [0, 2]


def test_direct_slash_command_is_routed_without_calling_the_model_handler() -> None:
    called: list[str] = []

    def handler(line: str, history: list[Message]) -> str:
        called.append(line)
        return "x"

    out = _run("/agents\n/exit\n", handler)
    assert "cashier" in out          # the roster was listed directly
    assert called == []              # the LLM handler was never invoked for a direct command


def test_help_lists_commands_and_unknown_slash_is_flagged() -> None:
    out = _run("/help\n/nope\n/exit\n", lambda line, history: "x")
    assert "Commands" in out and "/verify" in out
    assert "unknown command '/nope'" in out


def test_ctrl_c_mid_turn_cancels_and_returns_to_the_prompt() -> None:
    # A handler that raises KeyboardInterrupt (Ctrl-C mid-turn) must not end the session:
    # the turn is cancelled, nothing is added to history, and the next turn runs clean.
    seen: list[int] = []

    def handler(line: str, history: list[Message]) -> str:
        seen.append(len(history))
        if line == "boom":
            raise KeyboardInterrupt
        return f"echo: {line}"

    out = _run("boom\nafter\n/exit\n", handler)
    assert "cancelled" in out
    assert "echo: after" in out          # the session kept going after the cancel
    assert seen == [0, 0]                 # the cancelled turn left history empty
    assert out.rstrip().endswith("bye")


def test_blank_lines_are_ignored() -> None:
    calls: list[str] = []
    _run("\n   \n/exit\n", lambda line, history: calls.append(line) or "x")
    assert calls == []  # no turn for empty input


def test_chat_command_refuses_non_tty() -> None:
    # CliRunner stdin/stdout are not TTYs, so the command must refuse rather than hang.
    result = CliRunner().invoke(app, ["chat"])
    assert result.exit_code == 2
    assert "interactive terminal" in result.output


def test_chat_command_refuses_json_logs() -> None:
    result = CliRunner().invoke(app, ["--json-logs", "chat"])
    assert result.exit_code == 2
    assert "not available with --json-logs" in result.output


def test_chat_turn_handler_threads_the_human_ask_into_the_dispatcher(monkeypatch) -> None:
    # The handler must pass the human-input function through to the dispatcher so the
    # interactive scope/gate prompts reach the person at the keyboard (decision D).
    from finlexpurple.cli import _chat_turn_handler
    from finlexpurple.providers import factory
    from finlexpurple.tui import dispatch
    from finlexpurple.tui.theme import make_console

    captured: dict = {}
    monkeypatch.setattr(factory, "create_provider", lambda *a, **k: object())
    monkeypatch.setattr(dispatch, "dispatch_turn", lambda **kw: captured.update(kw) or "ok")

    def ask(_prompt: str) -> str:
        return "y"

    handler = _chat_turn_handler(make_console(file=io.StringIO(), no_color=True), ask)
    assert handler("hi", []) == "ok"
    assert captured["ask"] is ask
