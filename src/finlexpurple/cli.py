"""Command-line interface for FinLexPurple."""

from __future__ import annotations

import os
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path
from typing import Annotated

import typer
from dotenv import dotenv_values, set_key

from finlexpurple import __version__
from finlexpurple.config import Config, ConfigurationError
from finlexpurple.evidence.bundle import BundleFormatError
from finlexpurple.evidence.verify import verify_bundle
from finlexpurple.gates.authorization import record_attestation
from finlexpurple.gates.fix_mode import FixModeError, resolve_fix_mode
from finlexpurple.gates.kill_switch import KillSwitch
from finlexpurple.hardware.detect import detect_hardware
from finlexpurple.hardware.doctor import format_facts
from finlexpurple.hardware.profiles import hardware_profile, profile_names
from finlexpurple.hardware.wizard import run_setup
from finlexpurple.logging_setup import configure_logging
from finlexpurple.orchestrator.engine import run as run_orchestration
from finlexpurple.orchestrator.engine import run_id_for_resume, state_from_recon
from finlexpurple.orchestrator.iteration_limits import (
    IterationLimitConfigurationError,
    IterationLimits,
)
from finlexpurple.orchestrator.persistence import load_state
from finlexpurple.orchestrator.planner import Planner
from finlexpurple.orchestrator.state import InvalidRunStateError, RunState
from finlexpurple.providers.factory import create_provider
from finlexpurple.recon.crawler import ReconError, run_recon
from finlexpurple.scope.confirm import ScopeStorageError, confirm_scope
from finlexpurple.scope.enforcement import OutOfScopeError
from finlexpurple.scope.models import InvalidTargetError, ScopeDefinition, Target
from finlexpurple.security import isolation
from finlexpurple.security.audit_log import AuditLog
from finlexpurple.security.isolation import IsolationTier
from finlexpurple.security.safe_failure import SafeFailureController
from finlexpurple.tools.installed_check import check_tools, format_tool_report

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


def _load_and_validate_resume(state_path: Path) -> tuple[RunState, Target]:
    """Load a saved run and fully re-validate it before it is trusted for resume.

    Shared by ``scan --resume`` and ``resume <run-id>``: the run_id must match the
    target hash and be traversal-free, the file must live at
    ``<run_id>/run-state.json``, and the saved canonical target must already be
    normalized (an un-normalized target signals tampering). Exits 2 on any
    problem rather than raising a traceback.
    """

    try:
        state = load_state(state_path)
        run_id = run_id_for_resume(state)
        if state_path.name != "run-state.json" or state_path.parent.name != run_id:
            raise InvalidRunStateError("Cannot resume: state file path does not match its run_id.")
        normalized_target = Target.parse(state.canonical_target)
        if normalized_target.canonical != state.canonical_target:
            raise InvalidRunStateError("Cannot resume: saved canonical target is not normalized.")
        return state, normalized_target
    except (InvalidRunStateError, ValueError, OSError) as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from None


def _orchestrate_and_report(
    state: RunState,
    state_path: Path,
    normalized_target: Target,
    confirmed_scope: ScopeDefinition,
    fix_mode_value: str | None,
) -> None:
    """Record the authorization attestation + fix mode, then drive the engine under a kill switch.

    Shared tail for ``scan`` and ``resume``. Writes the run's tamper-evident
    audit log (Phase 7), records the authorization attestation (Phase 8, §28 #7)
    with the scope-confirmation timestamp, resolves the fix mode (Phase 8, §2),
    and arms the kill switch (Phase 8, §28 #8) around the orchestration so Ctrl+C
    halts gracefully at a safe point.
    """

    audit = AuditLog(state_path.parent / "audit.jsonl")
    attested_at = confirmed_scope.first_confirmed_at or datetime.now(timezone.utc)
    record_attestation(audit, target=normalized_target.canonical, attested_at=attested_at)
    typer.echo(
        f"Authorization attested for {normalized_target.canonical} "
        "(recorded in the run audit log)."
    )
    try:
        fix = resolve_fix_mode(fix_mode_value, interactive=False)
    except FixModeError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from None
    audit.record("fix_mode_selected", mode=fix.value)
    typer.echo(f"Fix mode: {fix.value}.")

    # A provider is optional: it only lets the planner reorder actions. If none
    # is configured, or configuration/construction fails, the scan proceeds with
    # the deterministic ordering rather than aborting.
    provider = None
    if os.environ.get("LLM_PROVIDER"):
        try:
            config = Config.load()
            provider = create_provider(config)
        except (ConfigurationError, ValueError, OSError):
            provider = None

    controller = SafeFailureController()

    def _on_kill() -> None:
        audit.record("kill_switch_engaged")

    kill_switch = KillSwitch(controller, on_stop=_on_kill)
    try:
        limits = IterationLimits.from_environment()
        with kill_switch:
            final_state = run_orchestration(
                state,
                state_path,
                planner=Planner(provider),
                limits=limits,
                controller=controller,
            )
    except (IterationLimitConfigurationError, OSError, ValueError) as exc:
        typer.echo(f"Orchestration could not continue safely: {exc}", err=True)
        raise typer.Exit(code=1) from None
    if final_state.stop_reason:
        typer.echo(f"Scan paused at stage {final_state.current_stage}: {final_state.stop_reason}")
        typer.echo(f"Resume with: finlexpurple resume {state_path.parent.name}")
    else:
        typer.echo(
            f"Orchestration complete: {final_state.counters['iterations']} iterations, "
            f"{final_state.counters['tool_calls']} detector calls. Phase 6 stub returned no findings."
        )


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
    tools: Annotated[
        bool,
        typer.Option(
            "--tools",
            help="Report external scanner tool availability instead of hardware facts.",
        ),
    ] = False,
) -> None:
    """Print hardware facts, or (with --tools) external scanner tool availability."""

    if tools:
        # Phase 7: the tool-availability doctor, distinct from the hardware doctor.
        typer.echo(format_tool_report(check_tools()))
        return
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
        str | None,
        typer.Option("--target", help="URL, IP/CIDR, or existing local directory to scope."),
    ] = None,
    resume: Annotated[
        Path | None,
        typer.Option("--resume", help="Resume from a saved run-state.json file."),
    ] = None,
    root_url: Annotated[
        str | None,
        typer.Option("--root-url", help="Starting HTTP(S) URL for an IP/CIDR scope."),
    ] = None,
    respect_robots: Annotated[
        bool,
        typer.Option("--respect-robots/--ignore-robots", help="Skip paths disallowed by robots.txt."),
    ] = False,
    request_delay: Annotated[
        float,
        typer.Option("--request-delay", min=0, max=60, help="Seconds between HTTP requests (default 0.5)."),
    ] = 0.5,
    fix_mode: Annotated[
        str | None,
        typer.Option("--fix-mode", help="'agent' or 'human' (default human); recorded for the fix stage (Phase 15)."),
    ] = None,
) -> None:
    """Confirm scope, map endpoints, and run the bounded orchestration loop.

    Two entry paths: a fresh scan from ``--target`` (confirm scope -> recon ->
    build initial state) or ``--resume`` of a saved ``run-state.json``. In both
    cases scope is confirmed and the Phase 6 engine is driven under
    ``IterationLimits``; the engine persists after every stage so an interrupted
    run is resumable. Exits non-zero on bad arguments, unconfirmed scope, unsafe
    recon, or an unsafe/mismatched resume, printing a specific message rather
    than a traceback.
    """

    if resume is not None and target is not None:
        typer.echo("--target cannot be combined with --resume; the saved target is used.", err=True)
        raise typer.Exit(code=2)
    if resume is None and target is None:
        typer.echo("--target is required unless --resume is supplied.", err=True)
        raise typer.Exit(code=2)
    state = None
    state_path: Path
    if resume is not None:
        state, normalized_target = _load_and_validate_resume(resume)
        state_path = resume
    else:
        assert target is not None
        try:
            normalized_target = Target.parse(target)
        except InvalidTargetError as exc:
            typer.echo(f"Invalid target: {exc}", err=True)
            raise typer.Exit(code=2) from None

    if normalized_target.kind == "directory":
        typer.echo("Web recon requires a URL or IP/CIDR scope; local directory recon is not implemented.", err=True)
        raise typer.Exit(code=2)
    if state is None and normalized_target.kind == "network" and root_url is None:
        typer.echo("IP/CIDR recon requires --root-url with an in-scope HTTP(S) hostname or address.", err=True)
        raise typer.Exit(code=2)
    if state is None and normalized_target.kind == "url" and root_url is not None:
        typer.echo("--root-url is only valid with an IP/CIDR --target.", err=True)
        raise typer.Exit(code=2)
    try:
        confirmed_scope = confirm_scope(normalized_target)
    except ScopeStorageError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from None
    if confirmed_scope is None:
        typer.echo("Scope was not confirmed; no scan was started.", err=True)
        raise typer.Exit(code=1)
    if state is None:
        start_url = root_url or normalized_target.canonical
        try:
            result = run_recon(
                confirmed_scope,
                start_url,
                request_delay=request_delay,
                respect_robots=respect_robots,
            )
        except (ReconError, OutOfScopeError) as exc:
            typer.echo(f"Recon could not start safely: {exc}", err=True)
            raise typer.Exit(code=1) from None
        state, state_path = state_from_recon(normalized_target.canonical, result)
        typer.echo(f"Recon: discovered {len(result.catalog)} endpoints.")
        for endpoint in result.catalog.endpoints:
            typer.echo(f"  {endpoint.method} {endpoint.url}")
            if endpoint.parameters:
                typer.echo(f"    Parameters: {', '.join(endpoint.parameters)}")
            if endpoint.content_type:
                typer.echo(f"    Content-Type: {endpoint.content_type}")
        if result.disallow_paths:
            typer.echo(f"Recon: recorded {len(result.disallow_paths)} robots.txt Disallow path hints.")
            for path in result.disallow_paths:
                typer.echo(f"  robots.txt Disallow: {path}")
        for warning in result.warnings:
            typer.echo(f"Recon warning: {warning}")
    elif state.canonical_target != normalized_target.canonical:
        typer.echo("Cannot resume: confirmed target does not match the saved canonical target.", err=True)
        raise typer.Exit(code=2)

    _orchestrate_and_report(state, state_path, normalized_target, confirmed_scope, fix_mode)


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


@app.command(name="setup-isolation")
def setup_isolation() -> None:
    """Choose the container-isolation tier and save it to .env (Phase 7).

    A separate first-run step from `setup` (the hardware wizard), by design — it
    does not touch the frozen Phase 2 wizard. The two may be merged into one
    `setup` command later (decisions.md §18 item 12).
    """

    choices = [tier.value for tier in IsolationTier]
    typer.echo("Container-isolation tiers (the scan runs inside this boundary):")
    typer.echo("  standard  (default) hardened Docker container — recommended")
    typer.echo("  none      runs on the host, no container boundary (less safe)")
    typer.echo("  maximum   gVisor sandbox — arrives in Phase 20")
    selected = (
        typer.prompt("Choose an isolation tier", default=IsolationTier.STANDARD.value)
        .strip()
        .lower()
    )
    if selected not in choices:
        typer.echo(f"Unknown tier {selected!r}; choose one of: {', '.join(choices)}", err=True)
        raise typer.Exit(code=2)
    tier = IsolationTier(selected)

    if tier is IsolationTier.NONE:
        typer.echo(
            "Warning: the None tier runs the scan directly on your host with no "
            "container boundary. Standard (Docker) is recommended."
        )
        if not typer.confirm("Run without container isolation?", default=False):
            typer.echo("No change made.")
            raise typer.Exit()
    if tier is IsolationTier.MAXIMUM:
        typer.echo("Note: the Maximum (gVisor) tier is built in Phase 20; Standard is used until then.")
    if tier is IsolationTier.STANDARD and not isolation.docker_available():
        typer.echo(
            "Note: Docker was not detected. Install and start Docker, or the scan "
            "will refuse to run under the Standard tier."
        )

    env_path = Path.cwd() / ".env"
    existing = dotenv_values(env_path) if env_path.exists() else {}
    old = existing.get(isolation.ISOLATION_ENV_VAR)
    if (
        old
        and old.strip().lower() != tier.value
        and not typer.confirm(
            f".env already sets {isolation.ISOLATION_ENV_VAR}={old}. Replace it with {tier.value}?",
            default=False,
        )
    ):
        typer.echo(f"Existing {isolation.ISOLATION_ENV_VAR} preserved.")
        raise typer.Exit()
    try:
        set_key(env_path, isolation.ISOLATION_ENV_VAR, tier.value, quote_mode="auto", encoding="utf-8")
    except OSError as exc:
        typer.echo(f"Could not save {isolation.ISOLATION_ENV_VAR} to {env_path}: {exc}", err=True)
        raise typer.Exit(code=1) from None
    typer.echo(f"Saved {isolation.ISOLATION_ENV_VAR}={tier.value} to {env_path}.")


@app.command()
def resume(
    run_id: Annotated[
        str,
        typer.Argument(help="Run id (the directory name under finlexpurple-reports/) to resume."),
    ],
) -> None:
    """Resume a paused run by its run id.

    Resolves ``./finlexpurple-reports/<run-id>/run-state.json``, re-confirms
    scope, and continues from where the run stopped. Equivalent to
    ``scan --resume <path>`` but by id.
    """

    if "/" in run_id or "\\" in run_id or ".." in run_id:
        typer.echo("Invalid run id.", err=True)
        raise typer.Exit(code=2)
    state_path = Path.cwd() / "finlexpurple-reports" / run_id / "run-state.json"
    if not state_path.is_file():
        typer.echo(
            f"No run-state.json found for run id {run_id!r} under finlexpurple-reports/.",
            err=True,
        )
        raise typer.Exit(code=2)
    state, normalized_target = _load_and_validate_resume(state_path)
    try:
        confirmed_scope = confirm_scope(normalized_target)
    except ScopeStorageError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from None
    if confirmed_scope is None:
        typer.echo("Scope was not confirmed; nothing to resume.", err=True)
        raise typer.Exit(code=1)
    _orchestrate_and_report(state, state_path, normalized_target, confirmed_scope, None)


@app.command(name="verify-bundle")
def verify_bundle_command(
    bundle_path: Annotated[
        Path,
        typer.Argument(help="Path to an evidence bundle (.json) to verify."),
    ],
    expected_hash: Annotated[
        str | None,
        typer.Option(
            "--expected-hash",
            help="The content hash the report quoted; checks the full chain (optional).",
        ),
    ] = None,
) -> None:
    """Independently re-verify an evidence bundle — standalone and fully offline.

    Reads only the bundle file: no scan runs and no network is used. It
    recomputes the canonical content hash and compares it to the stored hash so
    a third party (auditor/client) can confirm the bundle was not altered, and,
    if ``--expected-hash`` is given, that it matches the report. A present
    signature is reported but not cryptographically checked here (keyless
    verification needs connectivity); the hash check stands on its own. Exits
    non-zero if verification fails.
    """

    try:
        text = bundle_path.read_text(encoding="utf-8")
    except OSError as exc:
        typer.echo(f"Could not read bundle {bundle_path}: {exc}", err=True)
        raise typer.Exit(code=2) from None
    try:
        report = verify_bundle(text, expected_hash=expected_hash)
    except BundleFormatError as exc:
        typer.echo(f"Not a valid evidence bundle: {exc}", err=True)
        raise typer.Exit(code=2) from None

    for message in report.messages:
        typer.echo(f"  {message}")
    if report.ok:
        typer.echo("OK: bundle verified.")
    else:
        typer.echo("FAILED: bundle did not verify.", err=True)
        raise typer.Exit(code=1)


app.add_typer(telemetry_app, name="telemetry")
