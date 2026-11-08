"""Machine-readable JSON report — the frozen public contract (Phase 16; Unit 1.3).

``report.json`` is one of the three public contracts (CLI, report.json, bundle).
Its shape is frozen and versioned here:

* top-level ``schema_version``, ``tool`` (name+version), ``run_id``,
  ``started_at``/``generated_at`` (RFC 3339 UTC), and a ``target`` descriptor;
* a ``rules`` catalog (the stable rule_id records actually used in this report);
* every finding carries its ``rule_id`` and a structured ``location`` (url,
  method, normalized route template, and an optional real source file+line —
  never invented), plus an optional ``purl`` for dependency/container findings.

**Consumer rules (frozen):** ignore unknown fields; an **unknown status value
MUST be treated as ``inconclusive``**; ``verified``/``human_confirmed`` are never
renamed; minor versions only add optional fields. Paths are relative only — no
absolute local path ever appears in ``report.json``. Summary figures come from
``aggregate.py`` (code-computed, never LLM-written).
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from typing import Any
from urllib.parse import urlsplit

from finlexpurple import __version__
from finlexpurple.detectors.schema import Finding, route_template
from finlexpurple.reporting.aggregate import ReportSummary
from finlexpurple.reporting.rule_catalog import rule_record

REPORT_SCHEMA_VERSION = 1


def _target_descriptor(target: str) -> dict[str, Any]:
    """A small structured descriptor of the scan target (never an absolute path)."""

    parts = urlsplit(target)
    descriptor: dict[str, Any] = {"raw": target}
    if parts.scheme and parts.netloc:
        descriptor["scheme"] = parts.scheme.lower()
        descriptor["host"] = (parts.hostname or "").lower()
        if parts.port is not None:
            descriptor["port"] = parts.port
    return descriptor


def _finding_document(finding: Finding) -> dict[str, Any]:
    """The finding's canonical dict plus its rule_id and structured location."""

    record = rule_record(finding.vulnerability_class)
    doc = finding.to_dict()
    doc["rule_id"] = record.rule_id
    doc["location"] = {
        "url": finding.url,
        "method": finding.method,
        "route_template": route_template(finding.url),
        "source_file": finding.source_file,
        "source_line": finding.source_line,
    }
    return doc


def report_document(
    *,
    target: str,
    run_id: str,
    started_at: str,
    generated_at: str,
    summary: ReportSummary,
    findings: Sequence[Finding],
    tool_version: str | None = None,
) -> dict[str, Any]:
    """Build the full, schema_version-stamped report as a plain dict.

    This is the **single source of truth** for ``report.json``'s content: the JSON
    writer serializes exactly this dict, and other emitters (e.g. the SARIF writer,
    Unit 3.1) transform exactly this dict, so they can never drift from the report.
    ``rules`` carries only the catalog records actually used in this report, keyed by
    ``rule_id``, and each finding doc carries its ``rule_id`` and structured location.
    """

    used_rules = {}
    for finding in findings:
        record = rule_record(finding.vulnerability_class)
        used_rules[record.rule_id] = record.to_dict()

    return {
        "schema_version": REPORT_SCHEMA_VERSION,
        "tool": {"name": "finlexpurple", "version": tool_version or __version__},
        "run_id": run_id,
        "target": _target_descriptor(target),
        "started_at": started_at,
        "generated_at": generated_at,
        "summary": summary.to_dict(),
        "rules": used_rules,
        "findings": [_finding_document(finding) for finding in findings],
    }


def render_json(
    *,
    target: str,
    run_id: str,
    started_at: str,
    generated_at: str,
    summary: ReportSummary,
    findings: Sequence[Finding],
    tool_version: str | None = None,
) -> str:
    """Render the full, schema_version-stamped report as indented JSON text."""

    document = report_document(
        target=target,
        run_id=run_id,
        started_at=started_at,
        generated_at=generated_at,
        summary=summary,
        findings=findings,
        tool_version=tool_version,
    )
    return json.dumps(document, indent=2, ensure_ascii=True, sort_keys=True) + "\n"
