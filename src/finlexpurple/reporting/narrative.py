"""Finding explanations, grounded or templated (Phase 16; §6, Phase 11 reuse).

A plain-language explanation of a finding may come from an LLM, but it must pass
Phase 11's ``quote_grounding``: every substring it quotes from the evidence has
to actually appear in that finding's captured evidence. An explanation that
cites something not in the evidence is **rejected and never reaches the
report**; after a few attempts the module falls back to a deterministic template
built only from structured fields. The suggested fix is always template-based
(no LLM), so remediation text can never be fabricated.

The LLM is injected as an ``Explainer`` callable, so the reporting module itself
makes no provider call: a deployment wires the configured provider, and tests
pass a fake. Nothing here invents model output.
"""

from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field

from finlexpurple.detectors.schema import Finding
from finlexpurple.verifier.quote_grounding import UngroundedClaimError, ground_or_reject

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class Explanation:
    """An LLM explanation plus the exact evidence substrings it quotes.

    ``quotes`` are checked against the finding's evidence by ``quote_grounding``;
    a quote not present there causes the whole explanation to be rejected.
    """

    text: str
    quotes: list[str] = field(default_factory=list)


# Produces a candidate explanation for a finding; may raise to signal no answer.
Explainer = Callable[[Finding], Explanation]


def template_explanation(finding: Finding) -> str:
    """A deterministic explanation from structured fields only (no LLM)."""

    return (
        f"A {finding.severity.value}-severity {finding.vulnerability_class} issue was "
        f"identified at {finding.url} (via {finding.method}). "
        f"Expected signal: {finding.expected_signal or 'n/a'}."
    )


def suggested_fix(finding: Finding) -> str:
    """Template-based remediation guidance (never LLM-generated)."""

    return _REMEDIATION.get(
        finding.vulnerability_class,
        "Review the finding against your threat model and remediate per your "
        "framework's secure-coding guidance for this class.",
    )


def build_narrative(finding: Finding, *, explainer: Explainer | None = None, max_attempts: int = 3) -> str:
    """Return a grounded LLM explanation, or the template if none passes.

    With no explainer, returns the template. With one, it is called up to
    ``max_attempts`` times; the first result whose quotes are all grounded is
    used. If every attempt is ungrounded (or the explainer errors), the template
    is returned — an ungrounded narrative never reaches the report.
    """

    if explainer is None:
        return template_explanation(finding)
    for attempt in range(1, max_attempts + 1):
        try:
            candidate = explainer(finding)
        except Exception as exc:  # noqa: BLE001 - any explainer failure falls back to the template
            logger.warning("Explainer raised on attempt %d; using template fallback: %s", attempt, exc)
            return template_explanation(finding)
        try:
            ground_or_reject(candidate.quotes, finding)
        except UngroundedClaimError as exc:
            logger.warning("Ungrounded explanation rejected on attempt %d: %s", attempt, exc)
            continue
        return candidate.text
    logger.warning("No grounded explanation after %d attempts; using template fallback.", max_attempts)
    return template_explanation(finding)


_REMEDIATION = {
    "sqli": "Use parameterized queries / prepared statements; never build SQL by string concatenation.",
    "xss": "Context-encode all output and apply a strict Content-Security-Policy.",
    "idor": "Enforce per-object authorization on every request; do not rely on unguessable ids.",
    "ssrf": "Validate and allow-list outbound destinations; block internal/link-local addresses.",
    "vulnerable_dependency": "Upgrade to a fixed version per the advisory, or apply the vendor patch.",
    "hallucinated_dependency": "Remove the package; verify every dependency exists on its real registry.",
    "payment_sdk_typosquat": "Remove the impostor package and install the official payment SDK.",
    "exposed_secret": "Revoke and rotate the exposed secret; remove it from source and use a secret store.",
    "insecure_deserialization": "Use a safe loader (e.g. yaml.safe_load) and never deserialize untrusted data.",
    "exposed_docker_socket": "Never mount the host Docker socket into a container.",
    "privileged_container": "Run the container unprivileged; drop capabilities and use a read-only root FS.",
}
