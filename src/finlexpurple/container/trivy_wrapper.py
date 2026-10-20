"""Wrap Trivy for container image CVEs (Phase 14; §20, §25).

We do not reimplement image scanning or the vulnerability database. We run the
real ``trivy`` through the hardened sandbox (argument list only, never the Docker
socket, never privileged), parse its real JSON, and copy its own vulnerability
fields verbatim into Finding objects — never paraphrasing (§20). If the binary
is absent the scan is skipped cleanly, never faked.

PROVISIONAL (flagged): trivy is not installed in this build environment, so the
parser is written against Trivy's documented ``--format json`` shape and fails
loudly on an unexpected one rather than guessing.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Sequence

from finlexpurple.detectors.schema import Finding, Severity
from finlexpurple.tools.registry import TOOL_REGISTRY, ExternalTool

logger = logging.getLogger(__name__)
_MAX_SNAPSHOT = 4000

ScannerRunner = Callable[[Sequence[str]], tuple[int, str, str]]

_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "unknown": Severity.INFO,
    "negligible": Severity.INFO,
}


class TrivyError(RuntimeError):
    """trivy failed to run or produced output that could not be parsed."""


def _severity(value: object) -> Severity:
    return _SEVERITY.get(str(value).strip().lower(), Severity.MEDIUM)


def parse_trivy_output(raw: str, *, agent: str = "container") -> list[Finding]:
    """Normalize trivy JSON into Finding objects without paraphrasing."""

    if not raw.strip():
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise TrivyError("trivy did not emit valid JSON.") from exc
    results = data.get("Results") if isinstance(data, dict) else None
    if results is None:
        raise TrivyError("Unexpected trivy JSON shape (expected a 'Results' key).")

    findings: list[Finding] = []
    for result in results:
        target = str(result.get("Target", "image")) if isinstance(result, dict) else "image"
        for vuln in (result.get("Vulnerabilities") or []):
            if not isinstance(vuln, dict):
                raise TrivyError("Unexpected trivy vulnerability entry.")
            vuln_id = str(vuln.get("VulnerabilityID", "UNKNOWN"))
            pkg = str(vuln.get("PkgName", ""))
            version = str(vuln.get("InstalledVersion", ""))
            findings.append(
                Finding.new(
                    vulnerability_class="container_image_vuln",
                    method="IMAGE",
                    url=f"image:{pkg}@{version}" if pkg else target,
                    payload=f"{pkg}@{version}:{vuln_id}",
                    response_snapshot=json.dumps(vuln, sort_keys=True)[:_MAX_SNAPSHOT],
                    expected_signal=f"{vuln_id}: {vuln.get('Title') or vuln.get('Description', '')}".strip(),
                    severity=_severity(vuln.get("Severity")),
                    agent=agent,
                )
            )
    return findings


def run_trivy(
    image: str,
    *,
    offline: bool = False,
    tool: ExternalTool | None = None,
    runner: ScannerRunner | None = None,
    timeout: float = 600,
    agent: str = "container",
) -> list[Finding]:
    """Scan a container image with trivy and return normalized findings (or [])."""

    args: list[str] = ["image", "--format", "json", "--quiet"]
    if offline:
        # Use the last-downloaded DB so an air-gapped run uses the current feed (§25).
        args += ["--skip-db-update", "--offline-scan"]
    args.append(image)
    if runner is not None:
        returncode, stdout, stderr = runner(args)
    else:
        resolved = tool or TOOL_REGISTRY["trivy"]
        if not resolved.is_installed():
            logger.warning("trivy is not installed; skipping the Trivy image scan.")
            return []
        res = resolved.run(args, timeout=timeout)
        if res.timed_out:
            raise TrivyError("trivy timed out.")
        returncode, stdout, stderr = res.returncode or 0, res.stdout, res.stderr
    if returncode != 0:
        raise TrivyError(f"trivy failed (exit {returncode}): {stderr.strip()[:500]}")
    return parse_trivy_output(stdout, agent=agent)
