"""Secrets detection across the source/dependency surface (Phase 13; §25).

Original engineering: scan a project tree for committed secrets. Each match is
**redacted** before it is stored — the finding records the pattern, the
location, and a masked preview, **never the raw secret value** (consistent with
the secrets-hygiene rule: we never write a discovered secret into a finding,
report, or log). Binary files, large files, and common vendor/VCS directories
are skipped.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from finlexpurple.detectors.schema import Finding, Severity

_MAX_FILE_BYTES = 2_000_000
_SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", "dist", "build", ".mypy_cache"}


@dataclass(frozen=True)
class SecretPattern:
    """A named secret signature and how severe a hit is."""

    name: str
    regex: re.Pattern[str]
    severity: Severity


# High-signal patterns only, to keep false positives low. Each is a well-known
# credential shape, not a generic "looks random" heuristic.
_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern("aws_access_key_id", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), Severity.HIGH),
    SecretPattern("github_token", re.compile(r"\bghp_[0-9A-Za-z]{36}\b"), Severity.HIGH),
    SecretPattern("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), Severity.HIGH),
    SecretPattern("stripe_secret_key", re.compile(r"\bsk_live_[0-9A-Za-z]{24,}\b"), Severity.CRITICAL),
    SecretPattern("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), Severity.HIGH),
    SecretPattern(
        "private_key_block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        Severity.CRITICAL,
    ),
)


def _redact(secret: str) -> str:
    """Mask a secret for evidence: keep a short prefix, hide the rest."""

    secret = secret.strip()
    if len(secret) <= 4:
        return "****"
    return f"{secret[:4]}{'*' * min(len(secret) - 4, 12)} (redacted, len={len(secret)})"


def scan_text(text: str, *, location: str) -> list[Finding]:
    """Scan one text blob, returning a redacted Finding per secret match."""

    findings: list[Finding] = []
    for line_no, line in enumerate(text.splitlines(), start=1):
        for pattern in _PATTERNS:
            for match in pattern.regex.finditer(line):
                where = f"{location}:{line_no}"
                findings.append(
                    Finding.new(
                        vulnerability_class="exposed_secret",
                        method="FILE",
                        url=where,
                        payload=f"{pattern.name}:{where}",
                        # Redacted preview only — the raw secret is never stored.
                        response_snapshot=f"{pattern.name} at {where}: {_redact(match.group(0))}",
                        expected_signal=f"possible {pattern.name} committed at {where}",
                        severity=pattern.severity,
                    )
                )
    return findings


def _candidate_files(root: Path) -> Iterable[Path]:
    for path in sorted(root.rglob("*")):
        if path.is_dir():
            continue
        if any(part in _SKIP_DIRS for part in path.parts):
            continue
        try:
            if path.stat().st_size > _MAX_FILE_BYTES:
                continue
        except OSError:
            continue
        yield path


def scan_path(root: Path) -> list[Finding]:
    """Scan every eligible text file under ``root`` for committed secrets."""

    findings: list[Finding] = []
    for path in _candidate_files(root):
        try:
            text = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            continue  # unreadable or binary — skip, don't guess
        findings.extend(scan_text(text, location=str(path)))
    return findings
