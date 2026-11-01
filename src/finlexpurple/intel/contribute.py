"""Opt-in contribution diff — categorical-only, user-reviewed, never auto-sent (Decision 2).

Off by default. When a user opts in, this builds a **human-readable diff they
review before anything leaves the machine**, containing ONLY categorical fields —
technology, vulnerability class, severity, outcome status. It never includes a
URL, parameter, payload, header, body, source, finding id, or secret. The CLI
does **not** transmit it; the user submits it manually as a PR/issue.

The sanitizer baseline is the RunState "names only" rule (the same privacy
guarantee that keeps request/response values out of persisted state): records are
built from an explicit allow-list of categorical keys, so nothing else can be
copied in. As defense in depth, the rendered diff is scanned with
``supplychain.secrets.scan_text`` and the whole contribution is **refused** if any
secret pattern appears. Contributions are tagged ``community`` provenance and
labeled advisory-only / quarantined — trust is never derived from a submitter
count.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass
from typing import Any

from finlexpurple.detectors.schema import Finding
from finlexpurple.supplychain.secrets import scan_text

# The ONLY keys a contribution record may carry. Anything else is never copied in.
_ALLOWED_KEYS = ("technology", "vuln_class", "severity", "status")


class ContributionError(RuntimeError):
    """A contribution could not be built safely (e.g. a secret was detected)."""


@dataclass(frozen=True)
class Contribution:
    """A reviewed-before-send, categorical-only contribution (never transmitted here)."""

    records: list[dict[str, str]]
    diff_text: str
    provenance: str = "community"
    quarantined: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "records": [dict(record) for record in self.records],
            "provenance": self.provenance,
            "quarantined": self.quarantined,
        }


def _categorical_record(finding: Finding, technology: str) -> dict[str, str]:
    """Build one record from the allow-listed categorical fields only."""

    # Built from a literal with exactly the allow-listed keys (_ALLOWED_KEYS): no
    # request/response value can be copied in, by construction.
    return {
        "technology": technology,
        "vuln_class": finding.vulnerability_class,
        "severity": finding.severity.value,
        "status": finding.status.value,
    }


def build_contribution(
    findings: Sequence[Finding], *, technology: str, provenance: str = "community"
) -> Contribution:
    """Build a categorical-only, de-duplicated contribution for user review.

    Raises :class:`ContributionError` if the rendered diff trips the secret
    scanner — the contribution is never emitted with a secret in it. The result
    is for the user to read and submit manually; nothing is sent from here.
    """

    seen: set[tuple[str, str, str, str]] = set()
    records: list[dict[str, str]] = []
    for finding in findings:
        record = _categorical_record(finding, technology)
        key = (record["technology"], record["vuln_class"], record["severity"], record["status"])
        if key not in seen:
            seen.add(key)
            records.append(record)

    lines = [
        "# FinLexPurple intelligence contribution (categorical-only; review before sending)",
        f"# provenance: {provenance} (advisory-only, quarantined until a maintainer reviews it)",
        "# contains NO urls, params, payloads, headers, bodies, source, or secrets",
        "",
    ]
    lines += [
        f"- technology={r['technology']} vuln_class={r['vuln_class']} "
        f"severity={r['severity']} status={r['status']}"
        for r in records
    ]
    diff_text = "\n".join(lines) + "\n"

    leaked = scan_text(diff_text, location="intel-contribution")
    if leaked:
        raise ContributionError(
            f"refusing to build a contribution: {len(leaked)} secret-like value(s) detected in the "
            "diff; nothing is emitted."
        )
    return Contribution(records=records, diff_text=diff_text, provenance=provenance, quarantined=True)
