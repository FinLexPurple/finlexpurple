"""Authorization / scope attestation (Phase 8; decisions.md §28 item 7).

Before testing a new target the operator must explicitly attest they are
authorized. That attestation is the existing scope-confirmation prompt (Phase 4
``confirm.py`` asks "Do you confirm that you are authorized to test this exact
target?" and refuses to proceed if declined); this module **records** that
attestation in the run's tamper-evident audit log (Phase 7) with its timestamp,
so there is a durable, non-repudiable record of who authorized what and when. It
strengthens — it does not replace — the scope-confirmation safety check.

(Design note: this records the scope-confirmation attestation rather than adding
a second prompt. See the report for this interpretation.)
"""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from finlexpurple.security.audit_log import AuditLog


class AuthorizationError(ValueError):
    """A target was about to be tested without a recorded authorization attestation."""


def record_attestation(
    audit_log: AuditLog,
    *,
    target: str,
    attested_at: datetime,
) -> dict[str, Any]:
    """Record an authorization attestation for ``target`` in the audit log.

    ``attested_at`` is when the operator actually attested (the scope
    confirmation timestamp). Returns the audit entry. Raises
    :class:`AuthorizationError` if no timestamp is supplied, since an
    un-timestamped attestation is not a valid record.
    """

    if attested_at is None:  # defensive: an attestation must be timestamped
        raise AuthorizationError(
            f"Refusing to proceed: no authorization attestation timestamp for {target!r}."
        )
    return audit_log.record(
        "authorization_attested",
        target=target,
        attested_at=attested_at.isoformat(),
    )
