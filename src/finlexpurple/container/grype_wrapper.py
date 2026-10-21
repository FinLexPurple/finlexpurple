"""Wrap Grype for container image CVEs (Phase 14; §20, §25).

We do not reimplement image scanning or the vulnerability database. We run the
real ``grype`` through the hardened sandbox, parse its real JSON, and copy its
own match fields verbatim into Finding objects — never paraphrasing (§20).
Skipped cleanly when absent.

PROVISIONAL (flagged): grype is not installed in this build environment; the
parser is written against Grype's documented ``-o json`` shape and fails loudly
on an unexpected one.
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
    "negligible": Severity.INFO,
    "unknown": Severity.INFO,
}


class GrypeError(RuntimeError):
    """grype failed to run or produced output that could not be parsed."""


def _severity(value: object) -> Severity:
    return _SEVERITY.get(str(value).strip().lower(), Severity.MEDIUM)


def parse_grype_output(raw: str, *, agent: str = "container") -> list[Finding]:
    """Normalize grype JSON into Finding objects without paraphrasing."""

    if not raw.strip():
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise GrypeError("grype did not emit valid JSON.") from exc
    if not isinstance(data, dict) or not isinstance(data.get("matches"), list):
        raise GrypeError("Unexpected grype JSON shape (expected a 'matches' list).")

    findings: list[Finding] = []
    for match in data["matches"]:
        if not isinstance(match, dict):
            raise GrypeError("Unexpected grype match entry.")
        vuln = match.get("vulnerability", {})
        artifact = match.get("artifact", {})
        vuln_id = str(vuln.get("id", "UNKNOWN"))
        name = str(artifact.get("name", ""))
        version = str(artifact.get("version", ""))
        findings.append(
            Finding.new(
                vulnerability_class="container_image_vuln",
                method="IMAGE",
                url=f"image:{name}@{version}" if name else "image",
                payload=f"{name}@{version}:{vuln_id}",
                response_snapshot=json.dumps(match, sort_keys=True)[:_MAX_SNAPSHOT],
                expected_signal=f"{vuln_id}: {vuln.get('description', '')}".strip(),
                severity=_severity(vuln.get("severity")),
                agent=agent,
            )
        )
    return findings


def run_grype(
    image: str,
    *,
    tool: ExternalTool | None = None,
    runner: ScannerRunner | None = None,
    timeout: float = 600,
    agent: str = "container",
) -> list[Finding]:
    """Scan a container image with grype and return normalized findings (or [])."""

    args: list[str] = ["-o", "json", image]
    if runner is not None:
        returncode, stdout, stderr = runner(args)
    else:
        resolved = tool or TOOL_REGISTRY["grype"]
        if not resolved.is_installed():
            logger.warning("grype is not installed; skipping the Grype image scan.")
            return []
        res = resolved.run(args, timeout=timeout)
        if res.timed_out:
            raise GrypeError("grype timed out.")
        returncode, stdout, stderr = res.returncode or 0, res.stdout, res.stderr
    if returncode != 0:
        raise GrypeError(f"grype failed (exit {returncode}): {stderr.strip()[:500]}")
    # A successful run always emits JSON; empty output means the tool failed, and
    # a security scan must never silently report "clean" from a failed run.
    if not stdout.strip():
        raise GrypeError(
            f"grype produced no output (exit {returncode}); refusing to report a clean "
            f"result from a failed run. stderr: {stderr.strip()[:500]}"
        )
    return parse_grype_output(stdout, agent=agent)
