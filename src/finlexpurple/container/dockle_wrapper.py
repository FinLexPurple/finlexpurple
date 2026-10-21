"""Wrap Dockle for image best-practice / CIS checks (Phase 14; §20, §25).

We run the real ``dockle`` through the hardened sandbox, parse its real JSON,
and copy its own check fields verbatim into Finding objects — never paraphrasing
(§20). Only actionable levels (FATAL/WARN/INFO) become findings; PASS/SKIP/IGNORE
do not. Skipped cleanly when absent.

PROVISIONAL (flagged): dockle is not installed in this build environment; the
parser follows Dockle's documented ``-f json`` shape and fails loudly otherwise.
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

# Dockle levels; PASS/SKIP/IGNORE are not findings.
_LEVEL_SEVERITY = {
    "fatal": Severity.HIGH,
    "warn": Severity.MEDIUM,
    "info": Severity.LOW,
}


class DockleError(RuntimeError):
    """dockle failed to run or produced output that could not be parsed."""


def parse_dockle_output(raw: str, *, agent: str = "container") -> list[Finding]:
    """Normalize dockle JSON into Finding objects without paraphrasing."""

    if not raw.strip():
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise DockleError("dockle did not emit valid JSON.") from exc
    details = data.get("details") if isinstance(data, dict) else None
    if details is None:
        raise DockleError("Unexpected dockle JSON shape (expected a 'details' key).")

    findings: list[Finding] = []
    for detail in details:
        if not isinstance(detail, dict):
            raise DockleError("Unexpected dockle detail entry.")
        level = str(detail.get("level", "")).strip().lower()
        severity = _LEVEL_SEVERITY.get(level)
        if severity is None:
            continue  # PASS / SKIP / IGNORE — not a finding
        code = str(detail.get("code", "UNKNOWN"))
        findings.append(
            Finding.new(
                vulnerability_class="container_best_practice",
                method="IMAGE",
                url=f"dockle:{code}",
                payload=code,
                response_snapshot=json.dumps(detail, sort_keys=True)[:_MAX_SNAPSHOT],
                expected_signal=f"{code}: {detail.get('title', '')}".strip(),
                severity=severity,
                agent=agent,
            )
        )
    return findings


def run_dockle(
    image: str,
    *,
    tool: ExternalTool | None = None,
    runner: ScannerRunner | None = None,
    timeout: float = 600,
    agent: str = "container",
) -> list[Finding]:
    """Run dockle on a container image and return normalized findings (or [])."""

    args: list[str] = ["--format", "json", image]
    if runner is not None:
        returncode, stdout, stderr = runner(args)
    else:
        resolved = tool or TOOL_REGISTRY["dockle"]
        if not resolved.is_installed():
            logger.warning("dockle is not installed; skipping the Dockle image check.")
            return []
        res = resolved.run(args, timeout=timeout)
        if res.timed_out:
            raise DockleError("dockle timed out.")
        returncode, stdout, stderr = res.returncode or 0, res.stdout, res.stderr
    # dockle exits non-zero when it finds FATAL/WARN issues; JSON is still on stdout.
    if returncode not in (0, 1):
        raise DockleError(f"dockle failed (exit {returncode}): {stderr.strip()[:500]}")
    # A successful run always emits JSON; empty output means the tool failed, and
    # a security scan must never silently report "clean" from a failed run.
    if not stdout.strip():
        raise DockleError(
            f"dockle produced no output (exit {returncode}); refusing to report a clean "
            f"result from a failed run. stderr: {stderr.strip()[:500]}"
        )
    return parse_dockle_output(stdout, agent=agent)
