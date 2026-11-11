"""The chat scope prompt discloses the boundary, is fail-safe, and records like the CLI."""

from __future__ import annotations

import io
from pathlib import Path

from finlexpurple.scope.models import ScopeDefinition, Target
from finlexpurple.tui.scope_prompt import confirm_scope_in_chat
from finlexpurple.tui.theme import make_console


def _console() -> object:
    return make_console(file=io.StringIO(), no_color=True, width=80)


def _confirm(answer: str, target: str, tmp: Path, *, persist: bool = True):
    console = _console()
    scope = confirm_scope_in_chat(
        Target.parse(target),
        console=console,
        ask=lambda _p: answer,
        cache_directory=tmp,
        persist=persist,
    )
    return scope, console.file.getvalue()


def test_explicit_yes_confirms_persists_and_timestamps(tmp_path: Path) -> None:
    scope, out = _confirm("y", "https://example.com/app", tmp_path)
    assert isinstance(scope, ScopeDefinition)
    assert scope.first_confirmed_at is not None            # a fresh attestation timestamp
    assert "scope confirmed" in out
    # Persisted locally, exactly like the CLI confirmation records it.
    assert list(tmp_path.glob("*.json"))


def test_discloses_the_same_url_boundary_as_the_cli(tmp_path: Path) -> None:
    _, out = _confirm("yes", "https://example.com/app", tmp_path)
    assert "Resolved target: https://example.com/app" in out
    assert "Subdomains intended for enumeration: none" in out
    assert "Allowed URL boundary: exact host example.com" in out


def test_network_target_discloses_ip_boundary(tmp_path: Path) -> None:
    _, out = _confirm("y", "10.0.0.0/30", tmp_path)
    assert "Allowed IP boundary: 10.0.0.0/30" in out


def test_anything_but_yes_denies_fail_safe(tmp_path: Path) -> None:
    for answer in ("", "n", "no", "maybe", "authorized"):
        scope, out = _confirm(answer, "https://example.com/app", tmp_path)
        assert scope is None
        assert "scope not confirmed" in out
    # A denial writes nothing.
    assert not list(tmp_path.glob("*.json"))


def test_persist_false_confirms_without_writing(tmp_path: Path) -> None:
    scope, out = _confirm("y", "https://example.com/app", tmp_path, persist=False)
    assert isinstance(scope, ScopeDefinition)
    assert "scope confirmed" in out
    assert not list(tmp_path.glob("*.json"))
