"""Command-line interface for FinLexPurple."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path
from typing import Annotated

import typer

from finlexpurple import __version__
from finlexpurple.hardware.detect import detect_hardware
from finlexpurple.hardware.doctor import format_facts
from finlexpurple.hardware.profiles import hardware_profile, profile_names
from finlexpurple.hardware.wizard import run_setup
from finlexpurple.logging_setup import configure_logging
from finlexpurple.scope.confirm import ScopeStorageError, confirm_scope
from finlexpurple.scope.models import InvalidTargetError, Target

app = typer.Typer(help="Autonomous security testing agent.", invoke_without_command=True)
telemetry_app = typer.Typer(help="Manage optional telemetry.", no_args_is_help=True)


@app.callback(invoke_without_command=True)
def root_callback(
    ctx: typer.Context,
    json_logs: Annotated[
        bool,
        typer.Option("--json-logs", help="Write logs as machine-readable JSON lines."),
    ] = False,
    version: Annotated[
        bool,
        typer.Option("--version", help="Print the installed version and exit."),
    ] = False,
) -> None:
    """Set global CLI behavior before dispatching the selected command."""

    configure_logging(json_logs=json_logs)
    if version:
        typer.echo(__version__)
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())


def _stub(command: str, phase: int) -> None:
    typer.echo(f"{command} is not yet implemented (lands in Phase {phase})")


@app.command()
def setup(
    fake_hardware_profile: Annotated[
        str | None,
        typer.Option(
            "--fake-hardware-profile",
            help="Use synthetic hardware facts for a manual setup what-if run.",
        ),
    ] = None,
) -> None:
    """Configure hardware tier and model provider."""

    if fake_hardware_profile is not None and fake_hardware_profile not in profile_names():
        typer.echo(f"Unknown hardware profile. Choose one of: {', '.join(profile_names())}", err=True)
        raise typer.Exit(code=2)
    if not run_setup(fake_hardware_profile=fake_hardware_profile):
        raise typer.Exit(code=1)


@app.command()
def doctor(
    fake_hardware_profile: Annotated[
        str | None,
        typer.Option(
            "--fake-hardware-profile",
            help="Display a synthetic profile for a manual what-if run.",
        ),
    ] = None,
) -> None:
    """Print hardware facts without API keys or full filesystem paths."""

    if fake_hardware_profile is None:
        facts = detect_hardware()
    else:
        try:
            facts = hardware_profile(fake_hardware_profile)
        except ValueError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=2) from None
        typer.echo(f"Hardware source: synthetic profile {fake_hardware_profile}")
    typer.echo(format_facts(facts))


@app.command()
def init() -> None:
    """Create a local .env from the packaged template, without overwriting."""

    destination = Path.cwd() / ".env"
    if destination.exists():
        typer.echo(".env already exists; leaving it unchanged.")
        raise typer.Exit()
    try:
        template = files("finlexpurple").joinpath(".env.example").read_text(encoding="utf-8")
    except (FileNotFoundError, ModuleNotFoundError, OSError) as exc:
        typer.echo(f"Could not load the packaged .env.example template: {exc}", err=True)
        raise typer.Exit(code=1) from None
    try:
        with destination.open("x", encoding="utf-8", newline="\n") as env_file:
            env_file.write(template)
    except FileExistsError:
        typer.echo(".env already exists; leaving it unchanged.")
        raise typer.Exit()
    typer.echo(f"Created {destination}")


@app.command()
def scan(
    target: Annotated[
        str,
        typer.Option("--target", help="URL, IP/CIDR, or existing local directory to scope."),
    ],
) -> None:
    """Confirm a target's scope (scanning is added in later phases)."""

    try:
        normalized_target = Target.parse(target)
        confirmed_scope = confirm_scope(normalized_target)
    except InvalidTargetError as exc:
        typer.echo(f"Invalid target: {exc}", err=True)
        raise typer.Exit(code=2) from None
    except ScopeStorageError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from None
    if confirmed_scope is None:
        typer.echo("Scope was not confirmed; no scan was started.", err=True)
        raise typer.Exit(code=1)
    typer.echo("Scope confirmed. Scanning is not implemented yet.")


@telemetry_app.command()
def show() -> None:
    """Show telemetry settings (implemented in Phase 14)."""

    _stub("telemetry show", 14)


@telemetry_app.command()
def on() -> None:
    """Enable telemetry (implemented in Phase 14)."""

    _stub("telemetry on", 14)


@telemetry_app.command()
def off() -> None:
    """Disable telemetry (implemented in Phase 14)."""

    _stub("telemetry off", 14)


@app.command()
def feedback() -> None:
    """Submit run feedback (implemented in Phase 14)."""

    _stub("feedback", 14)


app.add_typer(telemetry_app, name="telemetry")
