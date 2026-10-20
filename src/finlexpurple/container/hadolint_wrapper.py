"""Wrap hadolint for Dockerfile linting (Phase 14; §20, §25).

We run the real ``hadolint`` through the hardened sandbox, parse its real JSON,
and copy its own message fields verbatim into Finding objects — never
paraphrasing (§20). Skipped cleanly when absent.

PROVISIONAL (flagged): hadolint is not installed in this build environment; the
parser follows hadolint's documented ``-f json`` shape (a top-level list) and
fails loudly otherwise.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable, Sequence
from pathlib import Path

from finlexpurple.detectors.schema import Finding, Severity
from finlexpurple.tools.registry import TOOL_REGISTRY, ExternalTool

logger = logging.getLogger(__name__)
_MAX_SNAPSHOT = 4000

ScannerRunner = Callable[[Sequence[str]], tuple[int, str, str]]

_LEVEL_SEVERITY = {
    "error": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "info": Severity.LOW,
    "style": Severity.INFO,
}


class HadolintError(RuntimeError):
    """hadolint failed to run or produced output that could not be parsed."""


def parse_hadolint_output(raw: str, *, agent: str = "container") -> list[Finding]:
    """Normalize hadolint JSON (a list of messages) into Findings, no paraphrase."""

    if not raw.strip():
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise HadolintError("hadolint did not emit valid JSON.") from exc
    if not isinstance(data, list):
        raise HadolintError("Unexpected hadolint JSON shape (expected a list).")

    findings: list[Finding] = []
    for message in data:
        if not isinstance(message, dict):
            raise HadolintError("Unexpected hadolint message entry.")
        code = str(message.get("code", "UNKNOWN"))
        file = str(message.get("file", "Dockerfile"))
        line = message.get("line", "?")
        level = str(message.get("level", "")).strip().lower()
        findings.append(
            Finding.new(
                vulnerability_class="dockerfile_lint",
                method="FILE",
                url=f"{file}:{line}",
                payload=f"{code}:{file}:{line}",
                response_snapshot=json.dumps(message, sort_keys=True)[:_MAX_SNAPSHOT],
                expected_signal=f"{code}: {message.get('message', '')}".strip(),
                severity=_LEVEL_SEVERITY.get(level, Severity.LOW),
                agent=agent,
            )
        )
    return findings


def run_hadolint(
    dockerfile: Path,
    *,
    tool: ExternalTool | None = None,
    runner: ScannerRunner | None = None,
    timeout: float = 120,
    agent: str = "container",
) -> list[Finding]:
    """Lint a Dockerfile with hadolint and return normalized findings (or [])."""

    # Absolute path: the sandbox runs in an isolated temp cwd, so a relative
    # Dockerfile path would not resolve and the lint would silently find nothing.
    args: list[str] = ["--format", "json", str(Path(dockerfile).resolve())]
    if runner is not None:
        returncode, stdout, stderr = runner(args)
    else:
        resolved = tool or TOOL_REGISTRY["hadolint"]
        if not resolved.is_installed():
            logger.warning("hadolint is not installed; skipping the Dockerfile lint.")
            return []
        res = resolved.run(args, timeout=timeout)
        if res.timed_out:
            raise HadolintError("hadolint timed out.")
        returncode, stdout, stderr = res.returncode or 0, res.stdout, res.stderr
    # hadolint exits 1 when it reports lint messages; JSON is still on stdout.
    if returncode not in (0, 1):
        raise HadolintError(f"hadolint failed (exit {returncode}): {stderr.strip()[:500]}")
    return parse_hadolint_output(stdout, agent=agent)
