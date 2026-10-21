"""Supply-chain module entry point (Phase 13; §25).

Runs the wrapped scanners (OSV-Scanner, pip-audit) and the original detections
(slopsquat, typosquat, secrets) over a project tree and returns normalized
Findings plus the mode and feed-staleness context the report must show (§25).

This is the module's own runnable surface; wiring it into ``scan --include
supplychain`` is deferred to the reporting/orchestrator phase (consistent with
the rest of the detection stack not yet being wired into ``scan``). Online
network access for the slopsquat/typosquat oracle is injected, so this module
performs no outbound request itself — the egress-checked oracle is supplied by
the caller (§15).
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from finlexpurple.detectors.schema import Finding
from finlexpurple.supplychain import feeds, secrets, slopsquat, typosquat
from finlexpurple.supplychain.feeds import FeedStatus
from finlexpurple.supplychain.mode import ScanMode
from finlexpurple.supplychain.osv_wrapper import run_osv_scanner
from finlexpurple.supplychain.pip_audit_wrapper import run_pip_audit
from finlexpurple.tools.registry import TOOL_REGISTRY

logger = logging.getLogger(__name__)

ScannerRunner = Callable[[Sequence[str]], tuple[int, str, str]]
_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9._-]+)")


@dataclass(frozen=True)
class SupplyChainResult:
    """Everything a report needs from a supply-chain run."""

    findings: list[Finding]
    mode: ScanMode
    feed_status: FeedStatus
    warnings: list[str] = field(default_factory=list)


def read_dependencies(project_path: Path) -> list[tuple[str, str]]:
    """Extract (name, ecosystem) pairs from requirements.txt and package.json.

    Deliberately minimal: enough to feed the slopsquat/typosquat checks, not a
    full resolver (that is the wrapped scanners' job, not ours).
    """

    deps: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()

    req = project_path / "requirements.txt"
    if req.is_file():
        for line in req.read_text(encoding="utf-8").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith(("#", "-")):
                continue
            match = _REQ_LINE.match(stripped)
            if match:
                entry = (match.group(1).lower(), "PyPI")
                if entry not in seen:
                    seen.add(entry)
                    deps.append(entry)

    pkg = project_path / "package.json"
    if pkg.is_file():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            data = {}
        for section in ("dependencies", "devDependencies"):
            block = data.get(section, {}) if isinstance(data, dict) else {}
            if isinstance(block, dict):
                for name in block:
                    entry = (str(name).lower(), "npm")
                    if entry not in seen:
                        seen.add(entry)
                        deps.append(entry)
    return deps


def scan_supplychain(
    project_path: Path,
    *,
    mode: ScanMode = ScanMode.OFFLINE,
    existence_oracle: slopsquat.ExistenceOracle | None = None,
    osv_runner: ScannerRunner | None = None,
    pip_audit_runner: ScannerRunner | None = None,
) -> SupplyChainResult:
    """Run the full supply-chain module over ``project_path``.

    ``mode`` selects live-oracle (online) vs shipped-list (offline) behavior for
    the slopsquat/typosquat checks and is recorded in every finding. The scanner
    runners are injectable so tests (and environments without the binaries
    installed) exercise the normalization without a real tool.
    """

    findings: list[Finding] = []
    warnings: list[str] = []

    # Wrapped scanners (real exit/JSON parsed into Findings; skipped if absent).
    # They manage their own vuln DB (download when absent); ``mode`` labels the
    # slopsquat/typosquat findings, not the scanners' DB behavior.
    if osv_runner is None and not TOOL_REGISTRY["osv-scanner"].is_installed():
        warnings.append("osv-scanner not installed; OSV dependency scan skipped.")
    else:
        findings.extend(run_osv_scanner(project_path, runner=osv_runner))

    requirements = project_path / "requirements.txt"
    if pip_audit_runner is None and not TOOL_REGISTRY["pip-audit"].is_installed():
        warnings.append("pip-audit not installed; pip-audit dependency scan skipped.")
    elif requirements.is_file() or pip_audit_runner is not None:
        findings.extend(run_pip_audit(requirements, runner=pip_audit_runner))

    # Original detections.
    deps = read_dependencies(project_path)
    findings.extend(slopsquat.check_dependencies(deps, mode=mode, oracle=existence_oracle))
    findings.extend(typosquat.check_dependencies(deps, mode=mode, oracle=existence_oracle))
    findings.extend(secrets.scan_path(project_path))

    return SupplyChainResult(
        findings=findings,
        mode=mode,
        feed_status=feeds.current_feed_status(),
        warnings=warnings,
    )
