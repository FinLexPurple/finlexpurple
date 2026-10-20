"""Wrap OSV-Scanner for dependency vulnerability matching (Phase 13; §20, §25).

We do **not** reimplement OSV's vulnerability database or matching. We run the
real ``osv-scanner`` through the hardened sandbox, parse its real JSON output,
and copy its own structured fields verbatim into Finding objects — never
paraphrasing its prose (§20). If the binary is absent the scan is skipped
cleanly (empty result), never faked.

PROVISIONAL (flagged): osv-scanner is not installed in this build environment,
so the exact CLI flags are version-dependent; the parser is written defensively
against the documented JSON shape and fails loudly on an unexpected one rather
than guessing. The offline flag passes OSV's local-database mode so an
air-gapped run uses the last-refreshed feed (§25).
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

# Runs osv-scanner args; returns (returncode, stdout, stderr). Injectable for tests.
ScannerRunner = Callable[[Sequence[str]], tuple[int, str, str]]


class OSVScannerError(RuntimeError):
    """osv-scanner failed to run or produced output that could not be parsed."""


def _severity_from_cvss(score: str) -> Severity:
    try:
        value = float(score)
    except (TypeError, ValueError):
        return Severity.MEDIUM
    if value >= 9.0:
        return Severity.CRITICAL
    if value >= 7.0:
        return Severity.HIGH
    if value >= 4.0:
        return Severity.MEDIUM
    if value > 0.0:
        return Severity.LOW
    return Severity.INFO


_NAMED_SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "moderate": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
}


def _severity_for(vuln: dict, group_max: str | None) -> Severity:
    """Derive severity from the tool's own fields; default MEDIUM, never guessed up."""

    named = vuln.get("database_specific", {})
    if isinstance(named, dict):
        label = str(named.get("severity", "")).strip().lower()
        if label in _NAMED_SEVERITY:
            return _NAMED_SEVERITY[label]
    if group_max is not None:
        return _severity_from_cvss(group_max)
    return Severity.MEDIUM


def parse_osv_output(raw: str, *, agent: str = "supplychain") -> list[Finding]:
    """Normalize osv-scanner JSON into Finding objects without paraphrasing.

    Reads ``results[].packages[].vulnerabilities[]`` and stores each vulnerability
    object verbatim as the evidence snapshot. Raises :class:`OSVScannerError` on
    invalid JSON or an unexpected shape.
    """

    if not raw.strip():
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise OSVScannerError("osv-scanner did not emit valid JSON.") from exc
    if not isinstance(data, dict) or not isinstance(data.get("results"), list):
        raise OSVScannerError("Unexpected osv-scanner JSON shape (expected a 'results' list).")

    findings: list[Finding] = []
    for result in data["results"]:
        source_path = str((result.get("source") or {}).get("path") or "dependencies")
        for package in result.get("packages", []):
            pkg = package.get("package", {}) if isinstance(package, dict) else {}
            name = str(pkg.get("name", "unknown"))
            version = str(pkg.get("version", ""))
            ecosystem = str(pkg.get("ecosystem", ""))
            group_max = _group_max_severity(package.get("groups", []))
            for vuln in package.get("vulnerabilities", []):
                if not isinstance(vuln, dict):
                    raise OSVScannerError("Unexpected osv-scanner vulnerability entry.")
                vuln_id = str(vuln.get("id", "UNKNOWN"))
                findings.append(
                    Finding.new(
                        vulnerability_class="vulnerable_dependency",
                        method="SCA",
                        url=f"pkg:{ecosystem}/{name}@{version}" if ecosystem else source_path,
                        payload=f"{name}@{version}:{vuln_id}",
                        # Verbatim tool data as evidence — not a paraphrase.
                        response_snapshot=json.dumps(vuln, sort_keys=True)[:_MAX_SNAPSHOT],
                        expected_signal=f"{vuln_id}: {vuln.get('summary', '')}".strip(),
                        severity=_severity_for(vuln, group_max),
                        agent=agent,
                    )
                )
    return findings


def _group_max_severity(groups: object) -> str | None:
    if not isinstance(groups, list):
        return None
    for group in groups:
        if isinstance(group, dict) and group.get("max_severity") not in (None, ""):
            return str(group["max_severity"])
    return None


def run_osv_scanner(
    project_path: Path,
    *,
    offline: bool = False,
    tool: ExternalTool | None = None,
    runner: ScannerRunner | None = None,
    timeout: float = 300,
    agent: str = "supplychain",
) -> list[Finding]:
    """Run osv-scanner over a project tree and return normalized findings (or [])."""

    args: list[str] = ["--format", "json", "--recursive", str(project_path)]
    if offline:
        # Use OSV's local database so an air-gapped run uses the last-refreshed feed.
        args.insert(0, "--offline-vulnerabilities")
    if runner is not None:
        returncode, stdout, stderr = runner(args)
    else:
        resolved = tool or TOOL_REGISTRY["osv-scanner"]
        if not resolved.is_installed():
            logger.warning("osv-scanner is not installed; skipping OSV dependency scan.")
            return []
        result = resolved.run(args, timeout=timeout)
        if result.timed_out:
            raise OSVScannerError("osv-scanner timed out.")
        returncode, stdout, stderr = result.returncode or 0, result.stdout, result.stderr
    # osv-scanner exits 1 when vulnerabilities are found; 0 when none. Other = error.
    if returncode not in (0, 1):
        raise OSVScannerError(f"osv-scanner failed (exit {returncode}): {stderr.strip()[:500]}")
    return parse_osv_output(stdout, agent=agent)
