"""Synthetic tests for scope confirmation and local persistence."""

from __future__ import annotations

import ntpath
import os
from pathlib import Path

import pytest
import typer

from finlexpurple.scope import models as scope_models
from finlexpurple.scope.confirm import (
    ScopeStorageError,
    _cache_path,
    _load_cached_scope,
    _save_scope,
    confirm_scope,
    user_config_directory,
)
from finlexpurple.scope.enforcement import OutOfScopeError, _filesystem_path_contains, enforce_scope
from finlexpurple.scope.models import ScopeDefinition, Target


def _patch_prompts(monkeypatch: pytest.MonkeyPatch, answers: list[bool]) -> tuple[list[str], list[str]]:
    output: list[str] = []
    questions: list[str] = []
    monkeypatch.setattr(typer, "echo", output.append)

    def confirm(question: str, *, default: bool = False) -> bool:
        questions.append(question)
        return answers.pop(0)

    monkeypatch.setattr(typer, "confirm", confirm)
    return output, questions


def test_new_target_shows_exact_scope_and_persists_after_confirmation(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    output, questions = _patch_prompts(monkeypatch, [True])
    target = Target.parse("HTTPS://Example.com:443/app")

    confirmed = confirm_scope(target, cache_directory=tmp_path / "scopes")

    assert confirmed is not None
    assert confirmed.target.canonical == "https://example.com/app"
    assert confirmed.first_confirmed_at is not None
    assert len(questions) == 1
    assert any("Resolved target: https://example.com/app" in line for line in output)
    assert any("Subdomains intended for enumeration: none" in line for line in output)
    assert len(list((tmp_path / "scopes").glob("*.json"))) == 1


def test_same_canonical_target_does_not_prompt_again(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    output, questions = _patch_prompts(monkeypatch, [True])
    cache = tmp_path / "scopes"
    first = confirm_scope(Target.parse("https://example.com:443/app/"), cache_directory=cache)
    second = confirm_scope(Target.parse("HTTPS://EXAMPLE.COM/app/"), cache_directory=cache)

    assert first is not None and second is not None
    assert first.first_confirmed_at == second.first_confirmed_at
    assert len(questions) == 1
    assert any("Scope already confirmed" in line for line in output)


def test_declining_does_not_create_a_confirmation(monkeypatch, tmp_path: Path) -> None:
    _patch_prompts(monkeypatch, [False])

    result = confirm_scope(Target.parse("https://example.com/"), cache_directory=tmp_path)

    assert result is None
    assert list(tmp_path.glob("*.json")) == []


def test_scope_change_invalidates_cached_confirmation(monkeypatch, tmp_path: Path) -> None:
    _patch_prompts(monkeypatch, [True, True])
    cache = tmp_path / "scopes"
    target = Target.parse("https://example.com/app")
    confirm_scope(target, cache_directory=cache)
    cache_file = _cache_path(target, cache)
    changed = ScopeDefinition.for_target(target).model_copy(update={"allow_paths": ("/other",)})
    cache_file.write_text(changed.model_dump_json(), encoding="utf-8")

    output: list[str] = []
    monkeypatch.setattr(typer, "echo", output.append)
    questions: list[str] = []

    def confirm(question: str, *, default: bool = False) -> bool:
        questions.append(question)
        return True

    monkeypatch.setattr(typer, "confirm", confirm)
    refreshed = confirm_scope(target, cache_directory=cache)

    assert refreshed is not None
    assert len(questions) == 1
    assert any("Resolved target" in line for line in output)


def test_local_directory_uses_the_same_confirmation_flow(monkeypatch, tmp_path: Path) -> None:
    output, _ = _patch_prompts(monkeypatch, [True])
    target_dir = tmp_path / "source"
    target_dir.mkdir()

    confirmed = confirm_scope(Target.parse(target_dir), cache_directory=tmp_path / "scopes")

    assert confirmed is not None
    assert confirmed.target.kind == "directory"
    assert confirmed.allow_paths == (os.path.normcase(str(target_dir.resolve())),)
    assert not any("Subdomains intended for enumeration" in line for line in output)


def test_windows_case_variants_share_scope_and_cache_key(monkeypatch, tmp_path: Path) -> None:
    root = r"C:\Users\Engineer\Project"
    case_variant = r"c:\users\engineer\project"
    with monkeypatch.context() as windows_semantics:
        windows_semantics.setattr(scope_models.os.path, "normcase", ntpath.normcase)
        first_target = Target(
            kind="directory", canonical=ntpath.normcase(root), local_path=Path(root)
        )
        second_target = Target(
            kind="directory",
            canonical=ntpath.normcase(case_variant),
            local_path=Path(case_variant),
        )
        cache = tmp_path / "scopes"
        first_scope = ScopeDefinition.for_target(first_target).confirmed()
        _save_scope(first_scope, cache)
        second_scope = _load_cached_scope(second_target, cache)

        assert second_target.canonical == first_target.canonical
        assert second_scope is not None
        assert first_scope.allow_paths == second_scope.allow_paths
        assert second_scope.target.local_path == Path(case_variant)
        assert _cache_path(first_target, cache) == _cache_path(second_target, cache)

    windows_path_functions = {
        "normcase": ntpath.normcase,
        "abspath": ntpath.abspath,
        "commonpath": ntpath.commonpath,
    }
    assert _filesystem_path_contains(root, case_variant, **windows_path_functions)
    assert not _filesystem_path_contains(
        root, r"C:\Users\Engineer\Project-copy", **windows_path_functions
    )

    real_root = tmp_path / "real-root"
    real_root.mkdir()
    with pytest.raises(OutOfScopeError):
        enforce_scope(ScopeDefinition.for_target(Target.parse(real_root)), tmp_path / "outside")


def test_unwritable_cache_does_not_return_confirmed_scope(monkeypatch, tmp_path: Path) -> None:
    _patch_prompts(monkeypatch, [True])
    file_instead_of_directory = tmp_path / "not-a-directory"
    file_instead_of_directory.write_text("", encoding="utf-8")

    with pytest.raises(ScopeStorageError, match="Could not save scope confirmation"):
        confirm_scope(Target.parse("https://example.com/"), cache_directory=file_instead_of_directory)


@pytest.mark.parametrize("platform", ["linux", "darwin", "win32"])
def test_cache_uses_platform_user_config_location(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, platform: str
) -> None:
    monkeypatch.setattr("finlexpurple.scope.confirm.sys.platform", platform)
    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path / "localappdata"))
    monkeypatch.setenv("APPDATA", str(tmp_path / "appdata"))

    result = user_config_directory()

    if platform == "win32":
        assert result == tmp_path / "localappdata" / "finlexpurple" / "scopes"
    elif platform == "darwin":
        assert result == tmp_path / "Library" / "Application Support" / "finlexpurple" / "scopes"
    else:
        assert result == tmp_path / "xdg" / "finlexpurple" / "scopes"
