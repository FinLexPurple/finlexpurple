"""Quote-grounding validation (Phase 11; decisions.md §6, hallucination control).

Before any human-facing claim about a finding (e.g. the Phase 13 narrative) is
accepted, every substring it explicitly quotes from the "evidence" must actually
appear in that finding's captured evidence. A claim that cites a value not
present in the evidence is rejected — this is what stops a generated explanation
from inventing detail the finding never contained. The check is deterministic
string containment, not a model judgment.
"""

from __future__ import annotations

from finlexpurple.detectors.schema import Finding


class UngroundedClaimError(ValueError):
    """A claim quoted evidence that is not present in the finding."""


def evidence_text(finding: Finding) -> str:
    """The concatenated captured evidence a claim may quote from."""

    parts = [
        finding.method,
        finding.url,
        finding.payload,
        finding.expected_signal,
        finding.response_snapshot or "",
        " ".join(f"{k}: {v}" for k, v in finding.headers.items()),
        finding.body or "",
    ]
    return "\n".join(parts)


def is_grounded(quotes: list[str], finding: Finding) -> bool:
    """True if every non-empty quote appears verbatim in the finding's evidence."""

    evidence = evidence_text(finding)
    return all((not quote) or (quote in evidence) for quote in quotes)


def ground_or_reject(quotes: list[str], finding: Finding) -> None:
    """Raise :class:`UngroundedClaimError` if any quote is not in the evidence."""

    evidence = evidence_text(finding)
    for quote in quotes:
        if quote and quote not in evidence:
            raise UngroundedClaimError(
                f"claim quotes {quote!r}, which is not present in the finding's evidence"
            )
