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


def scope_boundary_lines(target: Target) -> list[str]:
    """The human-readable scope-boundary disclosure shown before confirming a target.

    The single source of truth for the boundary lines an operator sees before
    attesting authorization — used by the CLI ``confirm_scope`` prompt and by the
    interactive chat scope prompt (``tui.scope_prompt``), so both front ends
    disclose exactly the same boundary before the human confirms.
    """

    lines = [f"Resolved target: {_display_target(target)}"]
    if target.kind == "url":
        lines.append("Subdomains intended for enumeration: none (exact target only).")
        lines.append(
            f"Allowed URL boundary: exact host {target.host}, same scheme and port, "
            f"path {target.path} and its descendants."
        )
    elif target.kind == "network":
        lines.append(f"Allowed IP boundary: {target.network}.")
    else:
        lines.append(
            f"Allowed filesystem boundary: {target.local_path} and descendants "
            "after resolving symlinks."
        )
    return lines


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


def save_confirmed_scope(scope: ScopeDefinition, *, cache_directory: Path | None = None) -> None:
    """Persist an already-confirmed scope atomically with owner-only (0600) permissions.

    The public entry point to the same atomic, private writer the CLI confirmation
    uses, so an alternative front end (the interactive chat scope prompt) records
    its confirmation identically. ``scope`` must already carry a confirmation
    timestamp; raises :class:`ScopeStorageError` if it cannot be written safely.
    """

    _save_scope(scope, cache_directory)


def confirm_scope(
    target: Target,
    *,
    cache_directory: Path | None = None,
    force: bool = False,
) -> ScopeDefinition | None:
    """Confirm a target's scope, prompting unless a prior confirmation applies.

    ``force=True`` always re-prompts and records a fresh confirmation, even if a
    prior one is cached — a fresh ``scan`` re-attests authorization on every run
    (the attestation timestamp in the audit log is then this run's, not a stale
    cached one). ``force=False`` (the default, used by ``resume``) reuses a valid
    cached confirmation without re-prompting so an in-progress run continues.
    """

    if not force:
        cached = _load_cached_scope(target, cache_directory)
        if cached is not None:
            confirmed_at = cached.first_confirmed_at
            if confirmed_at is not None:
                typer.echo(f"Scope already confirmed: {_display_target(target)}")
                typer.echo(f"First confirmed at: {confirmed_at.isoformat()}")
                return cached

    for line in scope_boundary_lines(target):
        typer.echo(line)
    if not typer.confirm("Do you confirm that you are authorized to test this exact target?", default=False):
        return None

    confirmed = ScopeDefinition.for_target(target).confirmed()
    _save_scope(confirmed, cache_directory)
    typer.echo(f"Scope confirmation saved locally for {_display_target(target)}.")
    return confirmed
