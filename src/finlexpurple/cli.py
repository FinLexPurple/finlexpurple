"""Command-line interface for FinLexPurple."""

from __future__ import annotations

import contextlib
import os
import sys
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from importlib.resources import files
from pathlib import Path
from typing import Annotated
from urllib.parse import urlsplit

import typer
from dotenv import dotenv_values, set_key

from finlexpurple import branding
from finlexpurple.agents import invoker as agent_invoker
from finlexpurple.agents.registry import AgentRequest, get_agent, registered_agents
from finlexpurple.config import DEFAULT_TELEMETRY_ENDPOINT, Config, ConfigurationError
from finlexpurple.detectors.prober import HttpProber
from finlexpurple.detectors.schema import Finding, FindingStatus
from finlexpurple.evidence.bundle import BundleFormatError
from finlexpurple.evidence.verify import verify_bundle
from finlexpurple.finance.idor_identities import IdorConfigError
from finlexpurple.finance.idor_identities import load_identities as load_idor_identities
from finlexpurple.finance.payment_tests import order_idor
from finlexpurple.gates.approval_gate import ApprovalGate
from finlexpurple.gates.authorization import record_attestation
from finlexpurple.gates.fix_mode import FixModeError, resolve_fix_mode
from finlexpurple.gates.kill_switch import KillSwitch
from finlexpurple.hardware.detect import detect_hardware
from finlexpurple.hardware.doctor import format_facts
from finlexpurple.hardware.profiles import hardware_profile, profile_names
from finlexpurple.hardware.wizard import run_setup
from finlexpurple.intel import cli_commands as intel_cli
from finlexpurple.logging_setup import configure_logging
from finlexpurple.orchestrator.engine import run as run_orchestration
from finlexpurple.orchestrator.engine import run_id_for_resume, state_from_recon
from finlexpurple.orchestrator.executor import Executor, WebDetector
from finlexpurple.orchestrator.iteration_limits import (
    IterationLimitConfigurationError,
    IterationLimits,
)
from finlexpurple.orchestrator.persistence import create_run_directory, load_state
from finlexpurple.orchestrator.planner import Planner
from finlexpurple.orchestrator.runstore import JsonRunStore, RunStore, get_run_store
from finlexpurple.orchestrator.state import InvalidRunStateError, RunState
from finlexpurple.providers.factory import create_provider
from finlexpurple.recon.crawler import ReconError, run_recon
from finlexpurple.recon.endpoint_catalog import Endpoint
from finlexpurple.recon.fingerprint import Fingerprint
from finlexpurple.reporting.output_layout import write_report
from finlexpurple.scope.confirm import ScopeStorageError, confirm_scope
from finlexpurple.scope.enforcement import OutOfScopeError
from finlexpurple.scope.models import InvalidTargetError, ScopeDefinition, Target
from finlexpurple.security import isolation
from finlexpurple.security.audit_log import AuditLog
from finlexpurple.security.budget import RateLimiter, RequestBudget
from finlexpurple.security.budget_guard import BudgetGuard, MeteredProvider
from finlexpurple.security.egress_policy import EgressPolicy
from finlexpurple.security.isolation import IsolationTier
from finlexpurple.security.safe_failure import SafeFailureController
from finlexpurple.selector.selector import select as select_specialists
from finlexpurple.telemetry import cli_commands as telemetry_cli
from finlexpurple.telemetry import collector as telemetry_collector
from finlexpurple.telemetry import feedback as telemetry_feedback
from finlexpurple.telemetry import sender as telemetry_sender
from finlexpurple.telemetry.install_counter import get_or_create_install_id
from finlexpurple.tools.installed_check import check_tools, format_tool_report
from finlexpurple.verifier.replay.canary import HttpCanary

# A per-run request kill-ceiling for the detection prober (§15 default-on cap).
_DETECTION_REQUEST_BUDGET = 2000

app = typer.Typer(help="Autonomous security testing agent.", invoke_without_command=True)
telemetry_app = typer.Typer(help="Manage optional telemetry.", no_args_is_help=True)
agents_app = typer.Typer(help="List and inspect the named security agents.", no_args_is_help=True)

# Frozen exit-code contract (Unit 1.4; see CONTRACTS.md):
#   0 = clean · 1 = tool/runtime error · 2 = usage/argument error ·
#   3 = --fail-on threshold matched (e.g. a VERIFIED finding).
_EXIT_VERIFIED_THRESHOLD = 3
# Reserved --format values now (sarif/cyclonedx/spdx arrive in Phase 3).
_REPORT_FORMATS = ("json", "md")
_FAIL_ON_CHOICES = ("none", "verified")


@app.callback(invoke_without_command=True)
def root_callback(
    ctx: typer.Context,
    json_logs: Annotated[
        bool,
        typer.Option("--json-logs", help="Write logs as machine-readable JSON lines."),
    ] = False,
    no_banner: Annotated[
        bool,
        typer.Option("--no-banner", help="Suppress the interactive brand banner."),
    ] = False,
    version: Annotated[
        bool,
        typer.Option("--version", help="Print the installed version and exit."),
    ] = False,
) -> None:
    """Set global CLI behavior before dispatching the selected command."""

    configure_logging(json_logs=json_logs)
    # The banner is cosmetic: machine-readable modes and an explicit opt-out
    # suppress it, and branding.py itself prints only to an interactive stderr.
    suppressed = no_banner or json_logs
    ctx.obj = {"no_banner": suppressed}
    if version:
        from finlexpurple.release import version_line

        # --version is machine-parseable: no banner, only the version on stdout.
        typer.echo(version_line())  # semver + cosmetic codename (§16)
        raise typer.Exit()
    if ctx.invoked_subcommand is None:
        branding.print_banner(suppressed=suppressed)
        typer.echo(ctx.get_help())


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


def _detection_origin(canonical_target: str) -> str | None:
    """Return the ``scheme://netloc`` origin to probe, or None if not a URL.

    Web detection rebuilds full endpoint URLs from ``origin`` + the persisted
    path. Only HTTP(S) targets have a usable origin here; a network (IP/CIDR)
    target's origin comes from the run's ``--root-url`` instead.
    """

    parts = urlsplit(canonical_target)
    if parts.scheme in ("http", "https") and parts.netloc:
        return f"{parts.scheme}://{parts.netloc}"
    return None


@dataclass(frozen=True)
class _SafetySettings:
    """Safety-relevant settings, tolerant of a model-provider misconfiguration.

    ``config`` is the validated :class:`Config` when it loaded, else ``None`` (the
    provider is unconfigured, so planning runs deterministically). The two safety
    values are always populated — from the loaded config, or recovered from the
    environment with the SAME validators when load failed — so an explicit
    ``REQUIRE_HUMAN_APPROVAL`` / ``MAX_SPEND_USD`` is honored rather than silently
    reset to a default. ``warning`` is a user-facing line when recovery happened.
    """

    config: Config | None
    require_human_approval: bool
    max_spend_usd: float
    warning: str | None = None


def _first_env(*names: str) -> tuple[str, str] | None:
    """Return (name, value) of the first set, non-empty env var among ``names``.

    Names are tried in order — the canonical ``FLP_``-prefixed name first, then its
    pre-0.4.0 back-compat alias — so the env-var freeze (Unit 1.4) honours both.
    """

    for name in names:
        raw = os.environ.get(name)
        if raw is not None and raw.strip() != "":
            return name, raw
    return None


def _build_run_store(*, reports_dir: Path | None = None) -> RunStore:
    """Build the run-state store selected by ``FLP_RUN_STORE`` (default: json).

    A bad value exits 2 (a usage error) rather than silently falling back, so a
    typo is caught loudly. SQLite is fully available by setting the env var.
    """

    found = _first_env("FLP_RUN_STORE")
    try:
        return get_run_store(found[1] if found else None, reports_dir=reports_dir)
    except ValueError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from None


def _recover_bool_env(*names: str, default: bool) -> bool:
    """Parse a boolean safety env var with Config's own validator; a bad value errors clearly."""

    found = _first_env(*names)
    if found is None:
        return default
    name, raw = found
    try:
        return bool(Config.validate_boolean(raw))
    except ValueError as exc:
        raise ConfigurationError(f"{name}: {exc}") from None


def _recover_spend_env(*names: str) -> float:
    """Parse the spend cap with Config's own validator; a bad value errors clearly."""

    found = _first_env(*names)
    if found is None:
        return 5.0
    name, raw = found
    try:
        return float(Config.validate_max_spend(raw))
    except ValueError as exc:
        raise ConfigurationError(f"{name}: {exc}") from None


def _load_safety_settings() -> _SafetySettings:
    """Load config; on failure warn clearly and recover the safety settings from the environment.

    Mirrors ``_telemetry_config``'s tolerant recovery. A provider/config error (for
    example a cloud provider with no key) must NOT silently drop the user's safety
    settings: ``REQUIRE_HUMAN_APPROVAL`` and ``MAX_SPEND_USD`` are re-read from the
    environment with the same validators (so ``false``/``0``/a number still apply),
    and planning proceeds deterministically with no provider. A genuinely
    unparseable SAFETY value raises its own clear :class:`ConfigurationError`
    instead of being coerced to a default.
    """

    try:
        config = Config.load()
    except (ConfigurationError, ValueError, OSError) as exc:
        require_human_approval = _recover_bool_env(
            "FLP_REQUIRE_HUMAN_APPROVAL", "REQUIRE_HUMAN_APPROVAL", default=True
        )
        max_spend_usd = _recover_spend_env("FLP_MAX_SPEND_USD", "MAX_SPEND_USD")
        warning = (
            f"Warning: configuration not fully loaded ({exc}). The model provider is "
            "unconfigured, so planning runs deterministically (no model call). Safety settings "
            f"were read from the environment: REQUIRE_HUMAN_APPROVAL={require_human_approval}, "
            f"MAX_SPEND_USD={max_spend_usd:.2f}."
        )
        return _SafetySettings(None, require_human_approval, max_spend_usd, warning)
    return _SafetySettings(config, config.require_human_approval, config.max_spend_usd, None)


def _orchestrate_and_report(
    state: RunState,
    store: RunStore,
    run_dir: Path,
    normalized_target: Target,
    confirmed_scope: ScopeDefinition,
    fix_mode_value: str | None,
    *,
    request_delay: float = 0.5,
    detect_origin: str | None = None,
    order_status_url: str | None = None,
    llm_plan: bool = False,
    report_formats: tuple[str, ...] | None = None,
    output: Path | None = None,
    fail_on: str = "none",
) -> None:
    """Record the authorization attestation + fix mode, then drive the engine under a kill switch.

    Shared tail for ``scan`` and ``resume``. Writes the run's tamper-evident
    audit log (Phase 7), records the authorization attestation (Phase 8, §28 #7)
    with the scope-confirmation timestamp, resolves the fix mode (Phase 8, §2),
    and arms the kill switch (Phase 8, §28 #8) around the orchestration so Ctrl+C
    halts gracefully at a safe point.
    """

    audit = AuditLog(run_dir / "audit.jsonl")
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

    # Safety settings are honored even when the model provider is misconfigured: a
    # provider/config error is reported loudly and planning falls back to
    # deterministic, but REQUIRE_HUMAN_APPROVAL / MAX_SPEND_USD are recovered from
    # the environment rather than silently reset (a genuinely bad safety value still
    # errors out). The dollar spend cap (§15) is always constructed.
    try:
        settings = _load_safety_settings()
    except ConfigurationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from None
    if settings.warning:
        typer.echo(settings.warning, err=True)
    max_spend_usd = settings.max_spend_usd
    require_human_approval = settings.require_human_approval

    # Planning is DETERMINISTIC by default (zero model calls — like the selector).
    # The model reorders actions only with --llm-plan, and only then is a provider
    # constructed, wrapped in a MeteredProvider so every call is charged against the
    # cap (no un-metered path to a paid API), and handed to the planner.
    provider = None
    if llm_plan and settings.config is not None and _first_env("FLP_LLM_PROVIDER", "LLM_PROVIDER"):
        try:
            provider = create_provider(settings.config)
        except (ConfigurationError, ValueError, OSError) as exc:
            typer.echo(
                f"Warning: could not construct the model provider ({exc}); "
                "planning runs deterministically.",
                err=True,
            )
            provider = None
    budget_guard = BudgetGuard(max_spend_usd)
    if provider is not None:
        provider = MeteredProvider(provider, budget_guard)
    plan_mode = "model-reordered" if provider is not None else "deterministic"
    typer.echo(
        f"Spend cap: ${budget_guard.max_spend_usd:.2f} (set MAX_SPEND_USD to change). "
        f"Planning: {plan_mode} (use --llm-plan to let the model reorder actions)."
    )

    controller = SafeFailureController()

    def _on_kill() -> None:
        audit.record("kill_switch_engaged")

    kill_switch = KillSwitch(controller, on_stop=_on_kill)

    # Wire the real web-detection + verification pipeline. Findings are collected
    # in memory and written only to the 0600 report tree — never into
    # run-state.json, which stays findings-empty by design (privacy guarantee).
    collected: list[Finding] = []
    origin = detect_origin or _detection_origin(state.canonical_target)
    executor: Executor | None = None
    canary_context: contextlib.AbstractContextManager[object] = contextlib.nullcontext()
    # Hoisted so the once-per-run order-IDOR step (below) can run after the loop.
    detection_prober: HttpProber | None = None
    run_financial = False
    idor_identities = None
    if origin is not None:
        prober = HttpProber(
            EgressPolicy.for_run(target_hosts=[urlsplit(origin).hostname or ""]),  # default-deny egress
            budget=RequestBudget(_DETECTION_REQUEST_BUDGET),  # §15 request kill-ceiling
            rate_limiter=RateLimiter(request_delay),
        )
        canary = HttpCanary()
        canary_context = canary
        fingerprint = Fingerprint(
            server=state.fingerprints.get("server"),
            technologies=tuple(state.fingerprints.get("technologies", [])),
        )
        # Scan front-door selector (Decision 1): one relevance pass over the fixed
        # registry decides which specialists are worth running, from LOCAL triage
        # text only (fingerprint + endpoint paths/param names — never bodies). The
        # live scan uses the zero-token deterministic selector (provider=None):
        # the bounded LLM pass is implemented and unit-tested but its live call
        # stays deferred so a spend-cap stop keeps its halt semantics (the
        # SpendBudgetExceededError invariant), which a selector-level fallback
        # would weaken.
        corpus_parts = [str(state.fingerprints.get("server") or "")]
        corpus_parts += [str(tech) for tech in state.fingerprints.get("technologies", [])]
        for record in state.catalog:
            corpus_parts.append(str(record.get("path", "")))
            corpus_parts += [str(name) for name in record.get("parameter_names", [])]
        selection = select_specialists("\n".join(corpus_parts), state.catalog, provider=None,
                                       fingerprint=fingerprint)
        run_financial = "cashier" in selection.agents
        detection_prober = prober
        # Order-IDOR identities are operator-supplied config; a malformed file is a
        # usage error (exit 2), not a silent skip. Loaded once here so the failure
        # surfaces during setup rather than mid-run.
        try:
            idor_identities = load_idor_identities()
        except IdorConfigError as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=2) from None
        typer.echo(
            f"Selector: {', '.join(selection.agents) or 'none'} "
            f"(relevance via {selection.source})."
        )
        for gap in selection.gaps:
            typer.echo(
                f"Capability gap: no registered specialist for {gap.technology} "
                f"({gap.vuln_class}) — a human must author and register one."
            )
        audit.record(
            "selector_selection",
            agents=list(selection.agents),
            source=selection.source,
            capability_gaps=[gap.technology for gap in selection.gaps],
        )
        # Price-tampering's verification re-execution is state-changing, so it is
        # gated (Phase 8). A scan is non-interactive: the default (approval
        # required) PAUSES the replay and the finding stays [REPORTED]; setting
        # REQUIRE_HUMAN_APPROVAL=false config-allows a standard-gate (cashier)
        # re-execution. Teller/Vault stay hard-gated and can never be allowed.
        gate = ApprovalGate(require_human_approval, interactive=False, audit_log=audit)

        def _charge_confirmer(finding: Finding, value: str) -> bool | None:
            # Genuine in-scope read-back via the egress-checked prober: re-read the
            # resource without the tampered input and see whether the manipulated
            # amount persisted. Never synthesize a charge — if the read-back cannot
            # be made, return None so the finding stays [REPORTED].
            try:
                return value in prober.request("GET", finding.url).text
            except Exception:  # noqa: BLE001 - any read-back failure = unconfirmable -> stays reported
                return None

        # Webhook-bypass settlement read-back from a SEPARATE operator-provided
        # order-status oracle (never the webhook URL itself); absent one it stays
        # INCONCLUSIVE, never VERIFIED.
        _settlement_confirmer = _settlement_confirmer_for(prober, order_status_url)

        executor = Executor(
            {"phase8_stub": WebDetector(
                origin=origin, prober=prober, sink=collected, fingerprint=fingerprint, canary=canary,
                gate=gate, charge_confirmer=_charge_confirmer,
                settlement_confirmer=_settlement_confirmer, run_financial=run_financial,
            )}
        )
    else:
        typer.echo("Note: web detection needs a URL origin; running recon/orchestration only.", err=True)

    try:
        limits = IterationLimits.from_environment()
        with kill_switch, canary_context:
            final_state = run_orchestration(
                state,
                store,
                planner=Planner(provider),
                executor=executor,
                limits=limits,
                controller=controller,
                budget_guard=budget_guard,
            )
    except (IterationLimitConfigurationError, OSError, ValueError) as exc:
        typer.echo(f"Orchestration could not continue safely: {exc}", err=True)
        raise typer.Exit(code=1) from None

    if final_state.stop_reason:
        typer.echo(f"Scan paused at stage {final_state.current_stage}: {final_state.stop_reason}")
        typer.echo(f"Model spend so far: ${final_state.spend_usd:.4f} of ${budget_guard.max_spend_usd:.2f}.")
        typer.echo(f"Resume with: finlexpurple resume {state.run_id}")
        return
    if origin is None:
        typer.echo(
            f"Orchestration complete: {final_state.counters['iterations']} iterations, "
            f"{final_state.counters['tool_calls']} detector calls; no web detectors ran."
        )
        return
    # Order IDOR (Unit 2.1): config-driven and once per run (the per-user resource
    # is behind login, so recon never discovers it). Runs only when the selector
    # chose cashier AND two identities are configured; a cross-account read is not
    # state-changing, so it is ungated. Without identities it is simply skipped —
    # order_idor is never silently verified.
    if detection_prober is not None and run_financial and idor_identities is not None:
        idor_findings = order_idor.run_order_idor(
            origin, agent="cashier", prober=detection_prober, identities=idor_identities,
        )
        collected.extend(idor_findings)
        if idor_findings:
            typer.echo(
                f"Order-IDOR: verified={sum(1 for f in idor_findings if f.status is FindingStatus.VERIFIED)}"
                f"/{len(idor_findings)} (two-session cross-account read)."
            )
    paths = write_report(
        collected,
        target=state.canonical_target,
        out_dir=output or run_dir,
        run_id=state.run_id,
        formats=report_formats,
    )
    audit.record("report_written", findings=len(collected))
    verified = sum(1 for f in collected if f.status is FindingStatus.VERIFIED)
    typer.echo(
        f"Scan complete: {len(collected)} findings ({verified} verified) "
        f"across {final_state.counters['tool_calls']} detector calls."
    )
    wanted = set(report_formats) if report_formats else {"json", "md"}
    if "md" in wanted:
        typer.echo(f"Report: {paths.report_md}")
    if "json" in wanted:
        typer.echo(f"        {paths.report_json}")
    # --fail-on verified (Unit 1.4): a distinct exit code when a verified finding
    # meets the threshold, so CI can gate on independently-reproduced findings.
    if fail_on == "verified" and verified > 0:
        typer.echo(
            f"Exiting {_EXIT_VERIFIED_THRESHOLD}: {verified} verified finding(s) met --fail-on verified.",
            err=True,
        )
        raise typer.Exit(code=_EXIT_VERIFIED_THRESHOLD)


@app.command()
def push() -> None:
    """Reserved: publish results to a FinLexPurple backend (not yet available)."""

    typer.echo(
        "The 'push' command is reserved and not available in this release.", err=True
    )
    raise typer.Exit(code=2)


@app.command()
def auth() -> None:
    """Reserved: authenticate to a FinLexPurple backend (not yet available)."""

    typer.echo(
        "The 'auth' command is reserved and not available in this release.", err=True
    )
    raise typer.Exit(code=2)


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


def _settlement_confirmer_for(
    prober: HttpProber, order_status_url: str | None
) -> Callable[[Finding], bool | None]:
    """Build the webhook-bypass settlement read-back from an operator-provided oracle.

    The forged callback's durable effect — did the order flip to paid? — is read
    from a SEPARATE, operator-provided order-status URL, never by re-reading the
    webhook endpoint (a webhook URL does not expose order state). Without an
    oracle URL a real read-back is impossible, so it returns ``None`` and the
    finding stays INCONCLUSIVE — never VERIFIED without a genuine read. With one,
    it substitutes the forged sentinel order id for a literal ``{order_id}``
    placeholder and GETs that URL through the egress-checked prober (in-scope
    only; an out-of-scope URL is blocked before any socket opens). It returns
    ``True`` only when the oracle genuinely shows that order paid, ``False`` when
    the read succeeds but the order is not paid (or absent), and ``None`` when the
    read cannot be made. A paid signal is never synthesized.
    """

    from finlexpurple.finance.payment_tests import webhook_bypass

    def confirm(finding: Finding) -> bool | None:
        del finding  # the forgery targets a fixed sentinel order; the oracle URL addresses it
        if not order_status_url:
            return None
        url = order_status_url.replace("{order_id}", webhook_bypass.FORGED_ORDER_ID)
        try:
            text = prober.request("GET", url).text
        except Exception:  # noqa: BLE001 - any read-back failure = unconfirmable -> inconclusive
            return None
        return webhook_bypass.PAID_MARKER in text and webhook_bypass.FORGED_ORDER_ID in text

    return confirm


@app.command()
def scan(
    ctx: typer.Context,
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
    order_status_url: Annotated[
        str | None,
        typer.Option(
            "--order-status-url",
            envvar="FLP_ORDER_STATUS_URL",
            help=(
                "In-scope order-status oracle URL for webhook-bypass settlement confirmation; "
                "may contain a literal {order_id} placeholder. Without it, a forged callback "
                "stays INCONCLUSIVE (never VERIFIED), since durable paid-state cannot be read."
            ),
        ),
    ] = None,
    llm_plan: Annotated[
        bool,
        typer.Option(
            "--llm-plan",
            envvar="FLP_LLM_PLAN",
            help=(
                "Use the configured model to reorder detector actions (costs a model call); "
                "off by default — ordering is deterministic and a default scan makes no model calls."
            ),
        ),
    ] = False,
    fix_mode: Annotated[
        str | None,
        typer.Option("--fix-mode", help="'agent' or 'human' (default human); recorded for the fix stage (Phase 15)."),
    ] = None,
    report_format: Annotated[
        list[str] | None,
        typer.Option(
            "--format",
            help="Report format(s) to write: 'json' and/or 'md' (default both). "
            "sarif/cyclonedx/spdx are reserved for a later release.",
        ),
    ] = None,
    output: Annotated[
        Path | None,
        typer.Option("--output", help="Directory to write the report into (default: the run directory)."),
    ] = None,
    fail_on: Annotated[
        str,
        typer.Option("--fail-on", help="Exit 3 when the threshold is met: 'none' (default) or 'verified'."),
    ] = "none",
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

    # Compact interactive brand line (stderr, TTY-only), never on parsed output.
    branding.print_brand_line(suppressed=bool((ctx.obj or {}).get("no_banner")))

    if resume is not None and target is not None:
        typer.echo("--target cannot be combined with --resume; the saved target is used.", err=True)
        raise typer.Exit(code=2)
    if resume is None and target is None:
        typer.echo("--target is required unless --resume is supplied.", err=True)
        raise typer.Exit(code=2)
    # Validate the frozen value sets for --format and --fail-on (Unit 1.4).
    formats = tuple(dict.fromkeys(report_format)) if report_format else None
    if formats is not None and any(fmt not in _REPORT_FORMATS for fmt in formats):
        typer.echo(f"--format must be one or more of {list(_REPORT_FORMATS)}.", err=True)
        raise typer.Exit(code=2)
    if fail_on not in _FAIL_ON_CHOICES:
        typer.echo(f"--fail-on must be one of {list(_FAIL_ON_CHOICES)}.", err=True)
        raise typer.Exit(code=2)
    state = None
    store: RunStore
    run_dir: Path
    if resume is not None:
        state, normalized_target = _load_and_validate_resume(resume)
        # `--resume <path>` is the JSON-file convenience: persist back to the same
        # run directory so a resumed run writes where it was paused.
        store = JsonRunStore(reports_dir=resume.parent.parent)
        run_dir = resume.parent
    else:
        assert target is not None
        try:
            normalized_target = Target.parse(target)
        except InvalidTargetError as exc:
            typer.echo(f"Invalid target: {exc}", err=True)
            raise typer.Exit(code=2) from None
        store = _build_run_store()

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
        # A fresh scan re-confirms authorization every run (fresh attestation),
        # rather than silently reusing a globally-cached confirmation.
        confirmed_scope = confirm_scope(normalized_target, force=True)
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
        state, handle = state_from_recon(normalized_target.canonical, result, store=store)
        run_dir = handle.directory
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

    _orchestrate_and_report(
        state,
        store,
        run_dir,
        normalized_target,
        confirmed_scope,
        fix_mode,
        request_delay=request_delay,
        detect_origin=_detection_origin(root_url) if root_url else None,
        order_status_url=order_status_url,
        llm_plan=llm_plan,
        report_formats=formats,
        output=output,
        fail_on=fail_on,
    )


def _telemetry_config() -> Config:
    """Load config for the telemetry commands, tolerant of LLM-provider misconfig.

    Telemetry does not depend on the model provider, so a provider configuration
    error must not break `telemetry`/`feedback`. Fall back to reading just the
    telemetry settings from the environment (``.env`` is already loaded by
    ``Config.load`` before it raises).
    """

    try:
        return Config.load()
    except ConfigurationError:
        enabled = os.environ.get("TELEMETRY_ENABLED", "").strip().lower() in {"true", "1", "yes", "on"}
        endpoint = os.environ.get("TELEMETRY_ENDPOINT") or DEFAULT_TELEMETRY_ENDPOINT
        return Config.model_construct(telemetry_enabled=enabled, telemetry_endpoint=endpoint)


@telemetry_app.command()
def show() -> None:
    """Show telemetry state and exactly what would be sent (opt-in; off by default)."""

    typer.echo(
        telemetry_cli.describe_telemetry(_telemetry_config(), install_id=get_or_create_install_id())
    )


@telemetry_app.command()
def on() -> None:
    """Opt in to telemetry (writes TELEMETRY_ENABLED=true to ./.env) and ping once."""

    typer.echo(telemetry_cli.enable_telemetry(Path.cwd() / ".env"))
    # Now that the user has opted in, send the one-time install ping.
    typer.echo(telemetry_cli.send_install_ping_once(_telemetry_config()))


@telemetry_app.command()
def off() -> None:
    """Opt out of telemetry (writes TELEMETRY_ENABLED=false to ./.env)."""

    typer.echo(telemetry_cli.disable_telemetry(Path.cwd() / ".env"))


@telemetry_app.command()
def reset() -> None:
    """Reset the local random install id (and its one-time ping marker)."""

    typer.echo(telemetry_cli.reset_install_id_text())


@app.command()
def feedback(
    run: Annotated[str, typer.Option("--run", help="Run id (directory under finlexpurple-reports/).")],
    rating: Annotated[
        str | None, typer.Option("--rating", help="Rate the run: good | ok | bad.")
    ] = None,
    finding: Annotated[
        str | None, typer.Option("--finding", help="Finding id to flag.")
    ] = None,
    mark: Annotated[
        str | None,
        typer.Option("--mark", help="Flag the finding: true-positive | false-positive."),
    ] = None,
) -> None:
    """Record run/finding feedback locally; send an allow-listed payload only if telemetry is on."""

    try:
        entry = telemetry_feedback.record_feedback(
            run_id=run, rating=rating, finding_id=finding, mark=mark
        )
    except telemetry_feedback.FeedbackError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=2) from None
    typer.echo(f"Feedback recorded locally for run {run}.")
    # Build an allow-listed payload (no run/finding id) and send only if enabled.
    payload = telemetry_collector.build_feedback_payload(
        run_rating=entry["rating"],
        finding_mark=entry["mark"],
        vulnerability_class=entry["vulnerability_class"],
    )
    result = telemetry_sender.send(payload, config=_telemetry_config())
    typer.echo(result.reason)


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
    reports_root = Path.cwd() / "finlexpurple-reports"
    store = _build_run_store(reports_dir=reports_root)
    run_dir = store.run_directory(run_id)
    if isinstance(store, JsonRunStore):
        # JSON backend: resolve the file and keep the established not-found message.
        state_path = run_dir / "run-state.json"
        if not state_path.is_file():
            typer.echo(
                f"No run-state.json found for run id {run_id!r} under finlexpurple-reports/.",
                err=True,
            )
            raise typer.Exit(code=2)
        state, normalized_target = _load_and_validate_resume(state_path)
    else:
        # SQLite (or any non-file) backend: load by id through the store.
        try:
            state = store.load_state(run_id)
            run_id_for_resume(state)
            normalized_target = Target.parse(state.canonical_target)
            if state.run_id != run_id or normalized_target.canonical != state.canonical_target:
                raise InvalidRunStateError("Cannot resume: stored run does not match its run id.")
        except (InvalidRunStateError, ValueError) as exc:
            typer.echo(str(exc), err=True)
            raise typer.Exit(code=2) from None
    try:
        confirmed_scope = confirm_scope(normalized_target)
    except ScopeStorageError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from None
    if confirmed_scope is None:
        typer.echo("Scope was not confirmed; nothing to resume.", err=True)
        raise typer.Exit(code=1)
    _orchestrate_and_report(state, store, run_dir, normalized_target, confirmed_scope, None)


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


@agents_app.command(name="list")
def agents_list() -> None:
    """Show the full named-agent roster (financial agents arrive in Phase 19)."""

    typer.echo("Named agents:")
    for item in registered_agents():
        where = "directly invocable" if item.directly_invocable else "runs within the full pipeline"
        requires = ", ".join(item.requires) or "none"
        typer.echo(f"  {item.name:9} [{item.phase:8}] {item.role}")
        typer.echo(f"            stage={item.stage}; requires={requires}; {where}")
    typer.echo("")
    typer.echo(
        "Financial agents: compass, cashier, teller (Phase 19a) and ledger, broker, vault, "
        "underwriter, courier (Phase 19b) are all available. Teller and Vault are hard-gated."
    )


@app.command(name="run")
def run_agent(
    agent: Annotated[str, typer.Option("--agent", help="Agent name (see `finlexpurple agents list`).")],
    target: Annotated[
        str | None, typer.Option("--target", help="URL to run the agent against.")
    ] = None,
    request_delay: Annotated[
        float, typer.Option("--request-delay", min=0, max=60, help="Seconds between HTTP requests.")
    ] = 0.5,
    order_status_url: Annotated[
        str | None,
        typer.Option(
            "--order-status-url",
            envvar="FLP_ORDER_STATUS_URL",
            help=(
                "In-scope order-status oracle URL for webhook-bypass settlement confirmation; "
                "may contain a literal {order_id} placeholder. Without it, a forged callback "
                "stays INCONCLUSIVE (never VERIFIED), since durable paid-state cannot be read."
            ),
        ),
    ] = None,
) -> None:
    """Run one named agent in isolation (fewer LLM calls than a full scan)."""

    resolved = get_agent(agent)
    if resolved is None:
        known = ", ".join(a.name for a in registered_agents())
        typer.echo(f"Unknown agent {agent!r}. Known agents: {known}.", err=True)
        raise typer.Exit(code=2)

    available: set[str] = set()
    normalized: Target | None = None
    if target is not None:
        try:
            normalized = Target.parse(target)
        except InvalidTargetError as exc:
            typer.echo(f"Invalid target: {exc}", err=True)
            raise typer.Exit(code=2) from None
        if normalized.kind != "url":
            typer.echo("Agent runs need a URL --target.", err=True)
            raise typer.Exit(code=2)
        available.add("target")

    # A clean explanation when the agent cannot run on its own — never a traceback.
    reason = agent_invoker.unavailable_reason(resolved, available)
    if reason is not None:
        typer.echo(reason, err=True)
        raise typer.Exit(code=2)
    assert normalized is not None  # a runnable stage agent reached here with a URL target

    # Same authorization safety as `scan`: confirm scope (fresh) and attest.
    try:
        confirmed_scope = confirm_scope(normalized, force=True)
    except ScopeStorageError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from None
    if confirmed_scope is None:
        typer.echo("Scope was not confirmed; the agent was not run.", err=True)
        raise typer.Exit(code=1)
    _, directory = create_run_directory(normalized.canonical)
    audit = AuditLog(directory / "audit.jsonl")
    record_attestation(
        audit,
        target=normalized.canonical,
        attested_at=confirmed_scope.first_confirmed_at or datetime.now(timezone.utc),
    )
    audit.record("agent_invoked", agent=resolved.name)
    typer.echo(f"Authorization attested for {normalized.canonical} (recorded in the run audit log).")

    origin = _detection_origin(normalized.canonical) or normalized.canonical
    prober = HttpProber(
        EgressPolicy.for_run(target_hosts=[urlsplit(origin).hostname or ""]),
        budget=RequestBudget(_DETECTION_REQUEST_BUDGET),
        rate_limiter=RateLimiter(request_delay),
    )

    def _recon(url: str) -> list[Endpoint]:
        return list(run_recon(confirmed_scope, url, request_delay=request_delay).catalog.endpoints)

    # Verification collaborators, so a financial specialist run in isolation reaches
    # VERIFIED exactly as in a scan: the same non-interactive gate policy (a default
    # run PAUSES the state-changing re-execution; REQUIRE_HUMAN_APPROVAL=false
    # config-allows a standard-gate agent, while Teller/Vault stay hard-gated) and
    # the same in-scope read-backs, which never synthesize a signal.
    try:
        settings = _load_safety_settings()
    except ConfigurationError as exc:
        typer.echo(str(exc), err=True)
        raise typer.Exit(code=1) from None
    if settings.warning:
        typer.echo(settings.warning, err=True)
    gate = ApprovalGate(settings.require_human_approval, interactive=False, audit_log=audit)

    def _charge_confirmer(finding: Finding, value: str) -> bool | None:
        try:
            return value in prober.request("GET", finding.url).text
        except Exception:  # noqa: BLE001 - any read-back failure = unconfirmable -> stays reported
            return None

    # Settlement read-back from the operator-provided order-status oracle
    # (--order-status-url, or its FLP_ORDER_STATUS_URL env fallback via typer);
    # absent one it stays INCONCLUSIVE, never VERIFIED.
    _settlement_confirmer = _settlement_confirmer_for(prober, order_status_url)

    request = AgentRequest(
        target=normalized.canonical, recon=_recon, prober=prober, gate=gate,
        charge_confirmer=_charge_confirmer, settlement_confirmer=_settlement_confirmer,
    )
    try:
        result = agent_invoker.invoke(resolved, request)
    except (ReconError, OutOfScopeError) as exc:
        typer.echo(f"Agent could not run safely: {exc}", err=True)
        raise typer.Exit(code=1) from None
    typer.echo(f"Agent '{result.agent}': {result.summary}")
    for finding in result.findings:
        typer.echo(
            f"  [{finding.status.value}] {finding.severity.value} "
            f"{finding.vulnerability_class} {finding.url}"
        )


app.add_typer(telemetry_app, name="telemetry")
app.add_typer(agents_app, name="agents")
app.add_typer(intel_cli.intel_app, name="intel")


def _is_top_level_help(argv: list[str]) -> bool:
    """True if ``argv`` is a top-level help request (a help flag before any subcommand).

    ``finlexpurple --help`` is top-level; ``finlexpurple scan --help`` is not (a
    subcommand precedes the flag), so the banner stays off subcommand help.
    """

    for token in argv:
        if token in ("--help", "-h"):
            return True
        if not token.startswith("-"):
            return False  # a subcommand (or its argument) came first
    return False


def main() -> None:
    """Console-script entrypoint: show the top-level banner, then run the app.

    Click handles ``--help`` with an eager option that exits before the group
    callback body runs, so the banner for top-level ``--help`` is printed here
    rather than in ``root_callback`` (which still prints it for the bare
    invocation). Both honor ``--no-banner``/``--json-logs`` and print only to an
    interactive stderr.
    """

    argv = sys.argv[1:]
    suppressed = "--no-banner" in argv or "--json-logs" in argv
    if _is_top_level_help(argv):
        branding.print_banner(suppressed=suppressed)
    app()


if __name__ == "__main__":
    main()
