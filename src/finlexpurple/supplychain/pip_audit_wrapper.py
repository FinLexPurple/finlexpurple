"""Wrap pip-audit for Python dependency advisory matching (Phase 13; §20, §25).

We do **not** reimplement pip-audit's advisory matching. We run the real
``pip-audit`` through the hardened sandbox, parse its real JSON output, and copy
its own fields verbatim into Finding objects — never paraphrasing (§20). If the
binary is absent the scan is skipped cleanly, never faked.

PROVISIONAL (flagged): pip-audit is not installed in this build environment. The
parser accepts both documented JSON shapes (a top-level list, and the newer
``{"dependencies": [...]}`` wrapper) and fails loudly on anything else.
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


class PipAuditError(RuntimeError):
    """pip-audit failed to run or produced output that could not be parsed."""


def parse_pip_audit_output(raw: str, *, agent: str = "supplychain") -> list[Finding]:
    """Normalize pip-audit JSON into Finding objects without paraphrasing.

    pip-audit does not emit a severity, so severity defaults to MEDIUM (never
    guessed upward); the vulnerability object is stored verbatim as evidence.
    """

    if not raw.strip():
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise PipAuditError("pip-audit did not emit valid JSON.") from exc

    if isinstance(data, dict) and isinstance(data.get("dependencies"), list):
        dependencies = data["dependencies"]
    elif isinstance(data, list):
        dependencies = data
    else:
        raise PipAuditError("Unexpected pip-audit JSON shape (expected a dependency list).")

    findings: list[Finding] = []
    for dep in dependencies:
        if not isinstance(dep, dict):
            raise PipAuditError("Unexpected pip-audit dependency entry.")
        name = str(dep.get("name", "unknown"))
        version = str(dep.get("version", ""))
        for vuln in dep.get("vulns", []):
            if not isinstance(vuln, dict):
                raise PipAuditError("Unexpected pip-audit vulnerability entry.")
            vuln_id = str(vuln.get("id", "UNKNOWN"))
            fix_versions = vuln.get("fix_versions") or []
            findings.append(
                Finding.new(
                    vulnerability_class="vulnerable_dependency",
                    method="SCA",
                    url=f"pkg:pypi/{name}@{version}",
                    payload=f"{name}@{version}:{vuln_id}",
                    response_snapshot=json.dumps(vuln, sort_keys=True)[:_MAX_SNAPSHOT],
                    expected_signal=(
                        f"{vuln_id}: {vuln.get('description', '')}".strip()
                        + (f" (fixed in {', '.join(map(str, fix_versions))})" if fix_versions else "")
                    ),
                    severity=Severity.MEDIUM,
                    agent=agent,
                )
            )
    return findings


def run_pip_audit(
    requirements: Path,
    *,
    tool: ExternalTool | None = None,
    runner: ScannerRunner | None = None,
    timeout: float = 300,
    agent: str = "supplychain",
) -> list[Finding]:
    """Run pip-audit against a requirements file and return normalized findings (or [])."""

    # Absolute path: the sandbox runs in an isolated temp cwd (see osv_wrapper).
    args: list[str] = ["--format", "json", "--requirement", str(Path(requirements).resolve())]
    if runner is not None:
        returncode, stdout, stderr = runner(args)
    else:
        resolved = tool or TOOL_REGISTRY["pip-audit"]
        if not resolved.is_installed():
            logger.warning("pip-audit is not installed; skipping the pip-audit dependency scan.")
            return []
        result = resolved.run(args, timeout=timeout)
        if result.timed_out:
            raise PipAuditError("pip-audit timed out.")
        returncode, stdout, stderr = result.returncode or 0, result.stdout, result.stderr
    # pip-audit exits non-zero when vulnerabilities are found; JSON still comes on stdout.
    if returncode not in (0, 1):
        raise PipAuditError(f"pip-audit failed (exit {returncode}): {stderr.strip()[:500]}")
    # A successful run always emits JSON; empty output means the tool failed, and
    # a security scan must never silently report "clean" from a failed run.
    if not stdout.strip():
        raise PipAuditError(
            f"pip-audit produced no output (exit {returncode}); refusing to report a clean "
            f"result from a failed run. stderr: {stderr.strip()[:500]}"
        )
    return parse_pip_audit_output(stdout, agent=agent)
