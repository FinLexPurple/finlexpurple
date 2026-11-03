"""The stable rule_id catalog and the severity -> SARIF-level map (Unit 1.3).

A reviewer reads this one file to see every check the tool can report and its
stable identifier. Two freezes live here:

* **rule_id is frozen equal to the detector's ``vulnerability_class``** — an id
  per check that never gets renamed. The fingerprint (Unit 1.2) already keys on
  ``vulnerability_class``; this module formalizes it as the public rule id and
  attaches a human title, a description, a default severity, and a family.
* **the severity -> SARIF level map** is documented and fixed: ``critical`` and
  ``high`` map to ``error``, ``medium`` to ``warning``, ``low``/``info`` to
  ``note``. A future SARIF writer (Unit 3.1) consumes exactly this map.

An unknown class (a new detector added before its catalog entry) gets a safe
fallback record rather than crashing the report writer, so the report is never
blocked — but the catalog is the source of truth and should carry every class.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from finlexpurple.detectors.schema import Severity

# Documented, fixed mapping from our severity scale to SARIF 2.1.0 result levels.
_SEVERITY_SARIF: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}
SARIF_LEVELS = frozenset(_SEVERITY_SARIF.values())


def sarif_level(severity: Severity) -> str:
    """Return the SARIF 2.1.0 level (``error``/``warning``/``note``) for a severity."""

    return _SEVERITY_SARIF[severity]


@dataclass(frozen=True)
class RuleRecord:
    """One catalog entry: a stable rule id and its fixed metadata."""

    rule_id: str
    title: str
    description: str
    default_severity: Severity
    family: str  # web | mcp | supplychain | container | financial | unknown

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "title": self.title,
            "description": self.description,
            "default_severity": self.default_severity.value,
            "family": self.family,
        }


def _rule(rule_id: str, title: str, description: str, severity: Severity, family: str) -> RuleRecord:
    return RuleRecord(rule_id, title, description, severity, family)


# The frozen catalog. rule_id == vulnerability_class for every entry.
RULE_CATALOG: dict[str, RuleRecord] = {
    rec.rule_id: rec
    for rec in (
        # web
        _rule("sqli", "SQL injection", "User input reaches a SQL query unparameterized.", Severity.HIGH, "web"),
        _rule("xss", "Cross-site scripting", "Unescaped user input is reflected into an HTML response.", Severity.MEDIUM, "web"),
        _rule("idor", "Insecure direct object reference", "A resource is addressable by id with no per-user authorization.", Severity.HIGH, "web"),
        _rule("ssrf", "Server-side request forgery", "The server can be induced to make requests to an attacker-chosen host.", Severity.HIGH, "web"),
        _rule("cache_poisoning", "Web cache poisoning", "An unkeyed input influences a cached response served to others.", Severity.MEDIUM, "web"),
        _rule("auth_misconfig", "Authentication misconfiguration", "An authentication or session control is missing or weak.", Severity.MEDIUM, "web"),
        _rule("generic_misconfig", "Security misconfiguration", "A security-relevant header or setting is missing or unsafe.", Severity.LOW, "web"),
        # mcp / ai agent
        _rule("prompt_injection", "Prompt injection", "Untrusted content can steer an AI agent's instructions.", Severity.HIGH, "mcp"),
        _rule("tool_poisoning", "MCP tool poisoning", "A tool description or result can manipulate the agent.", Severity.HIGH, "mcp"),
        _rule("data_exfiltration", "Agent data exfiltration", "An agent can be induced to leak in-context data out of band.", Severity.HIGH, "mcp"),
        # supply chain
        _rule("vulnerable_dependency", "Known-vulnerable dependency", "A declared dependency has a known advisory (OSV/pip-audit).", Severity.MEDIUM, "supplychain"),
        _rule("hallucinated_dependency", "Hallucinated dependency", "A referenced package does not exist in the live registry (slopsquat risk).", Severity.HIGH, "supplychain"),
        _rule("payment_sdk_typosquat", "Payment-SDK typosquat", "A dependency name impersonates a real payment SDK.", Severity.HIGH, "supplychain"),
        _rule("exposed_secret", "Exposed secret", "A credential-like value appears in source or config.", Severity.HIGH, "supplychain"),
        _rule("insecure_deserialization", "Insecure deserialization", "Untrusted data is deserialized through an unsafe loader.", Severity.HIGH, "supplychain"),
        # container
        _rule("container_image_vuln", "Container image vulnerability", "An installed OS/library package in the image has a known advisory.", Severity.MEDIUM, "container"),
        _rule("dockerfile_lint", "Dockerfile lint finding", "A Dockerfile instruction violates a build-security best practice.", Severity.LOW, "container"),
        _rule("container_best_practice", "Container best-practice finding", "An image configuration violates a hardening best practice.", Severity.LOW, "container"),
        # financial
        _rule("price_tampering", "Price tampering", "A client-supplied price/amount is trusted at checkout.", Severity.CRITICAL, "financial"),
        _rule("webhook_bypass", "Payment webhook bypass", "An unsigned/forged settlement callback is accepted as paid.", Severity.CRITICAL, "financial"),
    )
}


def rule_record(vulnerability_class: str) -> RuleRecord:
    """Return the catalog record for a class, or a safe fallback for an unknown one."""

    existing = RULE_CATALOG.get(vulnerability_class)
    if existing is not None:
        return existing
    return RuleRecord(
        rule_id=vulnerability_class,
        title=vulnerability_class,
        description="(no catalog entry; unrecognized rule id)",
        default_severity=Severity.MEDIUM,
        family="unknown",
    )
