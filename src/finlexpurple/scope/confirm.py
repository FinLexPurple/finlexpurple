"""Interactive target confirmation and private per-user scope persistence."""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
from pathlib import Path

import typer
from pydantic import ValidationError

from finlexpurple.scope.models import ScopeDefinition, Target

_APP_DIRECTORY = "finlexpurple"


class ScopeStorageError(OSError):
    """A confirmed scope could not be safely persisted locally."""


def user_config_directory() -> Path:
    """Return the platform's per-user configuration directory."""

    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
        root = Path(base) if base else Path.home() / "AppData" / "Local"
    elif sys.platform == "darwin":
        root = Path.home() / "Library" / "Application Support"
    else:
        root = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return root / _APP_DIRECTORY / "scopes"


def _cache_path(target: Target, cache_directory: Path | None = None) -> Path:
    digest = hashlib.sha256(f"{target.kind}\0{target.canonical}".encode()).hexdigest()
    return (cache_directory or user_config_directory()) / f"{digest}.json"


def _load_cached_scope(target: Target, cache_directory: Path | None) -> ScopeDefinition | None:
    path = _cache_path(target, cache_directory)
    try:
        cached = ScopeDefinition.model_validate_json(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, ValidationError):
        return None
    expected = ScopeDefinition.for_target(target)
    if (
        cached.target.kind != target.kind
        or cached.target.canonical != target.canonical
        or cached.first_confirmed_at is None
        or cached.allow_hosts != expected.allow_hosts
        or cached.allow_networks != expected.allow_networks
        or cached.allow_paths != expected.allow_paths
        or cached.deny_hosts != expected.deny_hosts
        or cached.deny_networks != expected.deny_networks
        or cached.deny_paths != expected.deny_paths
    ):
        return None
    return cached.model_copy(update={"target": target})


def _display_target(target: Target) -> str:
    if target.kind == "directory":
        return str(target.local_path)
    return target.canonical


def _save_scope(scope: ScopeDefinition, cache_directory: Path | None) -> None:
    path = _cache_path(scope.target, cache_directory)
    directory = path.parent
    temporary_path: Path | None = None
    try:
        directory.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            directory.chmod(0o700)
        with tempfile.NamedTemporaryFile(
            mode="w", encoding="utf-8", newline="\n", dir=directory, delete=False
        ) as cache_file:
            temporary_path = Path(cache_file.name)
            cache_file.write(scope.model_dump_json(indent=2))
            cache_file.write("\n")
            cache_file.flush()
            os.fsync(cache_file.fileno())
        if os.name != "nt":
            temporary_path.chmod(0o600)
        os.replace(temporary_path, path)
    except OSError as exc:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        raise ScopeStorageError(f"Could not save scope confirmation: {exc}") from None


def confirm_scope(
    target: Target,
    *,
    cache_directory: Path | None = None,
) -> ScopeDefinition | None:
    """Require explicit confirmation once for a canonical target and scope."""

    cached = _load_cached_scope(target, cache_directory)
    if cached is not None:
        confirmed_at = cached.first_confirmed_at
        if confirmed_at is not None:
            typer.echo(f"Scope already confirmed: {_display_target(target)}")
            typer.echo(f"First confirmed at: {confirmed_at.isoformat()}")
            return cached

    typer.echo(f"Resolved target: {_display_target(target)}")
    if target.kind == "url":
        typer.echo("Subdomains intended for enumeration: none (exact target only).")
        typer.echo(
            f"Allowed URL boundary: exact host {target.host}, same scheme and port, "
            f"path {target.path} and its descendants."
        )
    elif target.kind == "network":
        typer.echo(f"Allowed IP boundary: {target.network}.")
    else:
        typer.echo(
            f"Allowed filesystem boundary: {target.local_path} and descendants "
            "after resolving symlinks."
        )
    if not typer.confirm("Do you confirm that you are authorized to test this exact target?", default=False):
        return None

    confirmed = ScopeDefinition.for_target(target).confirmed()
    _save_scope(confirmed, cache_directory)
    typer.echo(f"Scope confirmation saved locally for {_display_target(target)}.")
    return confirmed
