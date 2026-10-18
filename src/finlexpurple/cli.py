"""Command-line interface for FinLexPurple."""

from __future__ import annotations

from importlib.resources import files
from pathlib import Path
from typing import Annotated

import typer

from finlexpurple import __version__
from finlexpurple.logging_setup import configure_logging

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
def setup() -> None:
    """Configure hardware and model provider (implemented in Phase 2/3)."""

    _stub("setup", 2)


@app.command()
def init() -> None:
    """Create a local .env from the packaged template, without overwriting."""

    destination = Path.cwd() / ".env"
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
def scan() -> None:
    """Scan a target (scope confirmation is added in Phase 4)."""

    _stub("scan", 4)


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
