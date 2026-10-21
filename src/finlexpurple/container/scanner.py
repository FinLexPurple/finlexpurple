"""Container module entry point (Phase 14; §25, §15).

Runs the wrapped scanners (Trivy, Grype, Dockle on an image; hadolint on a
Dockerfile) and the original escape/exposed-socket checks over a target, and
returns normalized Findings plus the mode and feed-staleness the report must
show (§25). Reuses the supply-chain module's offline-awareness primitives
(``mode``/``feeds``), since §25 governs both modules identically.

Wiring into ``scan --include container`` is deferred to the reporting/
orchestrator phase, consistent with the rest of the detection stack. This module
performs no Docker execution itself and never mounts the host socket / never runs
privileged (§15); the wrapped scanners run through the Phase 7 hardened sandbox.
"""

from __future__ import annotations

import logging
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

from finlexpurple.container import (
    dockle_wrapper,
    escape_checks,
    grype_wrapper,
    hadolint_wrapper,
    trivy_wrapper,
)
from finlexpurple.detectors.schema import Finding
from finlexpurple.supplychain.feeds import FeedStatus, current_feed_status
from finlexpurple.supplychain.mode import ScanMode
from finlexpurple.tools.registry import TOOL_REGISTRY

logger = logging.getLogger(__name__)

ScannerRunner = Callable[[Sequence[str]], tuple[int, str, str]]
_COMPOSE_NAMES = ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml")


@dataclass(frozen=True)
class ContainerResult:
    """Everything a report needs from a container run."""

    findings: list[Finding]
    mode: ScanMode
    feed_status: FeedStatus
    warnings: list[str] = field(default_factory=list)


def _load_compose(path: Path, warnings: list[str]) -> dict | None:
    """Parse a compose file if PyYAML is available; warn (not fail) otherwise."""

    try:
        import yaml  # type: ignore[import-untyped]  # PyYAML optional; guarded, no hard dep
    except ImportError:
        warnings.append("PyYAML not available; docker-compose escape checks skipped.")
        return None
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        warnings.append(f"could not parse {path.name}: {exc}")
        return None
    return data if isinstance(data, dict) else None


def scan_container(
    *,
    image: str | None = None,
    project_path: Path | None = None,
    runtime_config: dict | None = None,
    mode: ScanMode = ScanMode.OFFLINE,
    trivy_runner: ScannerRunner | None = None,
    grype_runner: ScannerRunner | None = None,
    dockle_runner: ScannerRunner | None = None,
    hadolint_runner: ScannerRunner | None = None,
) -> ContainerResult:
    """Run the container module over an image and/or a project directory.

    ``image`` is scanned by Trivy/Grype/Dockle; a Dockerfile under
    ``project_path`` is linted by hadolint and checked for escape posture; a
    compose file there is checked for escape classes; ``runtime_config`` (a
    ``docker inspect`` dict) is checked directly. Scanner runners are injectable
    so tests and tool-less environments exercise normalization without a binary.
    """

    findings: list[Finding] = []
    warnings: list[str] = []

    if image is not None:
        # Wrapped scanners manage their own vuln DB (download when absent); ``mode``
        # labels the offline-awareness of our own checks, not the scanners' DB.
        if trivy_runner is None and not TOOL_REGISTRY["trivy"].is_installed():
            warnings.append("trivy not installed; Trivy image scan skipped.")
        else:
            findings.extend(trivy_wrapper.run_trivy(image, runner=trivy_runner))
        if grype_runner is None and not TOOL_REGISTRY["grype"].is_installed():
            warnings.append("grype not installed; Grype image scan skipped.")
        else:
            findings.extend(grype_wrapper.run_grype(image, runner=grype_runner))
        if dockle_runner is None and not TOOL_REGISTRY["dockle"].is_installed():
            warnings.append("dockle not installed; Dockle image check skipped.")
        else:
            findings.extend(dockle_wrapper.run_dockle(image, runner=dockle_runner))

    if project_path is not None:
        dockerfile = project_path / "Dockerfile"
        if dockerfile.is_file():
            if hadolint_runner is None and not TOOL_REGISTRY["hadolint"].is_installed():
                warnings.append("hadolint not installed; Dockerfile lint skipped.")
            else:
                findings.extend(hadolint_wrapper.run_hadolint(dockerfile, runner=hadolint_runner))
            findings.extend(
                escape_checks.check_dockerfile(
                    dockerfile.read_text(encoding="utf-8"), location=str(dockerfile)
                )
            )
        for name in _COMPOSE_NAMES:
            compose = project_path / name
            if compose.is_file():
                data = _load_compose(compose, warnings)
                if data is not None:
                    findings.extend(escape_checks.check_compose(data, location=str(compose)))

    if runtime_config is not None:
        findings.extend(escape_checks.check_runtime_config(runtime_config))

    return ContainerResult(
        findings=findings,
        mode=mode,
        feed_status=current_feed_status(),
        warnings=warnings,
    )
