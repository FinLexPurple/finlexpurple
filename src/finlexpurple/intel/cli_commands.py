"""CLI commands for intelligence packs: ``intel show | pull | contribute`` (Decision 2).

Backing logic lives here (testable without Typer); ``cli.py`` mounts ``intel_app``.

* **show** — summarize the active pack: the verified local cache if present, else
  the shipped baseline (hash-only). Works fully air-gapped.
* **pull** — fetch + verify + cache the latest signed pack from the **baked**
  public channel (URL + pinned publishing-identity regexp), verifying the
  identity-pinned Sigstore signature. The channel is env-overridable for
  self-hosting; **clearing** a required override fails closed, and a download is
  never trusted without a verified pinned-identity signature.
* **contribute** — build a categorical-only contribution diff from a run's
  report for the user to review and submit **manually**. Nothing is transmitted.
"""

from __future__ import annotations

import json
import os
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated

import typer

from finlexpurple.detectors.schema import Finding
from finlexpurple.intel.baseline import load_baseline
from finlexpurple.intel.config import ConfigError, resolve_pull_channel
from finlexpurple.intel.contribute import build_contribution
from finlexpurple.intel.download import fetch_and_cache
from finlexpurple.intel.pack import Pack, PackValidationError, load_pack
from finlexpurple.security.egress_policy import EgressPolicy

_CACHE_PACK = "pack.json"


def default_cache_dir() -> Path:
    """Where a downloaded pack is cached (under the current working directory)."""

    return Path.cwd() / ".finlexpurple" / "intel-cache"


def active_pack(cache_dir: Path) -> tuple[Pack, str]:
    """Return the verified cached pack if present and valid, else the shipped baseline."""

    cached = cache_dir / _CACHE_PACK
    if cached.exists():
        try:
            return load_pack(cached.read_text(encoding="utf-8")), "cached (downloaded, signature-verified at pull)"
        except (OSError, PackValidationError):
            pass  # a bad cache never shadows the trustworthy baseline
    return load_baseline(), "baseline (shipped in the wheel, hash-only)"


def summary_text(pack: Pack, source: str) -> str:
    """A plain-text summary of a pack: its source, version, and pattern fingerprints."""

    lines = [
        f"Active intelligence pack: {source}",
        f"  version: {pack.manifest.version} (schema {pack.manifest.schema_version})",
        f"  patterns: {len(pack.patterns)}",
    ]
    lines += [
        f"    - {rec.fingerprint}: reorder {rec.ordered_agents} [{rec.provenance}]"
        for rec in pack.patterns
    ]
    lines.append("Packs are advisory-only: they reorder already-selected checks, never add/gate/verify.")
    return "\n".join(lines)


def pull_text(cache_dir: Path, *, allow_rollback: bool, env: Mapping[str, str] | None = None) -> str:
    """Fetch+verify+cache from the baked (or overridden) signed channel; fail closed on a cleared override."""

    env = env if env is not None else os.environ
    try:
        channel = resolve_pull_channel(env)
    except ConfigError as exc:
        return f"pull: refused — {exc}"
    result = fetch_and_cache(
        channel.pack_url, channel.signature_url,
        egress=EgressPolicy(list(channel.egress_hosts)), cache_dir=cache_dir,
        expected_identity=channel.expected_identity, expected_sha256=channel.expected_sha256,
        allow_rollback=allow_rollback,
    )
    return f"pull: {'ok' if result.ok else 'refused'} — {result.reason}"


def contribution_text(report_path: Path, *, technology: str) -> str:
    """Build a categorical-only contribution diff from a run's report.json (never sent)."""

    try:
        report = json.loads(report_path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise typer.BadParameter(f"could not read report {report_path}: {exc}") from None
    findings = [Finding.model_validate(item) for item in report.get("findings", [])]
    return build_contribution(findings, technology=technology).diff_text


intel_app = typer.Typer(help="Intelligence pattern packs (data-only, advisory-only).", no_args_is_help=True)


@intel_app.command("show")
def show() -> None:
    """Show the active intelligence pack (cached if present, else the shipped baseline)."""

    pack, source = active_pack(default_cache_dir())
    typer.echo(summary_text(pack, source))


@intel_app.command("pull")
def pull(
    allow_rollback: Annotated[
        bool, typer.Option("--allow-rollback", help="Permit installing an older pack.")
    ] = False,
) -> None:
    """Fetch, verify, and cache the latest signed pack (baked signed channel; env-overridable)."""

    typer.echo(pull_text(default_cache_dir(), allow_rollback=allow_rollback))


@intel_app.command("contribute")
def contribute(
    report: Annotated[Path, typer.Argument(help="Path to a run's report.json.")],
    technology: Annotated[
        str, typer.Option("--technology", help="Categorical technology label.")
    ] = "unknown",
) -> None:
    """Build a categorical-only contribution diff for you to review and submit manually."""

    typer.echo(contribution_text(report, technology=technology))
