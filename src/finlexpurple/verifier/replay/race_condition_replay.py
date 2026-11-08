"""Race-condition replay — a bounded, gated concurrency harness (Unit 2.5).

This is the deliberately conservative verification for a check-then-act race. It
re-executes the captured operation as a **bounded, rate-limited, gated** concurrent
burst and decides, by deterministic code, whether the server durably
double-processed the operation **this run**:

* ``REPRODUCED`` — a bounded concurrent burst ran (behind the approval gate) **and**
  an independent in-scope read-back confirms the operation was durably applied **more
  than once** (the check-then-act guard was bypassed: no idempotency key / lock). This
  is the ONLY outcome that yields ``verified``, and only when the double-processing is
  deterministically observed on this run. -> VERIFIED
* ``INCONCLUSIVE`` — everything else that ran: the read-back showed a single
  application this run, or could not confirm, or no read-back was available. A race is
  inherently non-deterministic, so a non-reproduction is a **human-review lead**, never
  evidence the race is absent. This is the *expected* outcome for a genuine race, and
  it is the correct, honest result — not a failure. (There is deliberately **no**
  ``NOT_REPRODUCED`` path: observing a race behave safely once never proves it safe.)
* ``BLOCKED`` — approval for the state-changing concurrent re-execution was not granted.
* ``NO_ENGINE`` — the replay could not run (no prober / gate). -> REPORTED

Concurrency here is always **bounded and single-shot**: exactly ``_BURST`` requests,
fired once, never a retry loop and never uncontrolled concurrency. The prober's own
``RequestBudget``/``RateLimiter`` still cap total volume, so this can never flood a
target. The whole burst is state-changing, so it routes through the Phase 8 approval
gate first; the gate category is the finding's own agent, so a Teller/Vault-origin
finding is hard-gated and can never auto-run. The LLM is never consulted; acceptance
of the concurrent requests is never enough for ``REPRODUCED`` — a confirmed durable
double-processing read-back is required, and the confirmer must read REAL in-scope
state, never synthesize a double-processing signal.
"""

from __future__ import annotations

import concurrent.futures
from collections.abc import Callable

from finlexpurple.detectors.prober import Prober
from finlexpurple.detectors.schema import Finding
from finlexpurple.gates.approval_gate import ApprovalGate, GateAction, GateOutcome
from finlexpurple.verifier.status import ReplayOutcome, ReplayResult

# Given the captured finding and the number of concurrent attempts the server
# accepted (2xx) in the burst, report whether durable in-scope state now shows the
# operation applied MORE THAN ONCE (True), shows a single application this run
# (False), or cannot be confirmed (None). A deployment wires this to a real in-scope
# read of the persisted state (a redemption-count / credited-balance oracle) and
# decides double-processing itself; it must observe real server state, never guess.
RaceConfirmer = Callable[[Finding, int], bool | None]

# Standard-gate default when a finding carries no agent (mirrors the other classes).
_DEFAULT_CATEGORY = "cashier"

# Gate outcomes under which a state-changing re-execution may proceed.
_PROCEED = (GateOutcome.APPROVED, GateOutcome.ALLOWED)

# The bounded concurrent burst size. Small and fixed: enough to expose a
# check-then-act window, never a flood, never a loop. The prober's RequestBudget
# caps total volume independently, so the two bounds compose.
_BURST = 2


def _fire_bounded_burst(prober: Prober, finding: Finding) -> int:
    """Fire exactly ``_BURST`` concurrent copies of the captured request; return the count accepted.

    Single-shot and bounded: ``_BURST`` requests, fired once, no retry. A request
    that errors (e.g. the prober's budget/limiter refuses it under concurrency)
    counts as not accepted rather than crashing the replay.
    """

    def _one() -> int:
        try:
            response = prober.request(finding.method, finding.url, headers=finding.headers or None)
        except Exception:  # noqa: BLE001 - a failed concurrent attempt counts as not accepted
            return 0
        return 1 if 200 <= response.status_code < 300 else 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=_BURST) as pool:
        futures = [pool.submit(_one) for _ in range(_BURST)]
        return sum(f.result() for f in concurrent.futures.as_completed(futures))


def replay(
    finding: Finding,
    prober: Prober | None,
    gate: ApprovalGate | None,
    race_confirmer: RaceConfirmer | None,
) -> ReplayResult:
    """Run a bounded, gated concurrent burst; reproduced only if durably double-processed this run."""

    if prober is None or gate is None:
        return ReplayResult(
            None, "race replay requires a prober and an approval gate; not provided.",
            outcome=ReplayOutcome.NO_ENGINE,
        )

    category = (finding.agent or _DEFAULT_CATEGORY).strip().lower()
    outcome = gate.resolve(GateAction(
        description=(
            f"bounded {_BURST}x concurrent double-processing probe on {finding.url}"
        ),
        category=category,
        state_changing=True,
    ))
    if outcome not in _PROCEED:
        return ReplayResult(
            None,
            f"not replayed: approval not granted for a state-changing concurrent re-execution "
            f"(gate outcome: {outcome.value}); replay blocked.",
            outcome=ReplayOutcome.BLOCKED,
        )

    accepted = _fire_bounded_burst(prober, finding)

    # REPRODUCED requires a confirmed durable double-processing; acceptance of the
    # concurrent requests alone is never sufficient, and no confirmer => inconclusive.
    if race_confirmer is None:
        return ReplayResult(
            None,
            f"fired a bounded {_BURST}-way concurrent burst ({accepted} accepted) but no in-scope "
            "read-back was available to confirm double-processing — inconclusive (human-review lead).",
            outcome=ReplayOutcome.INCONCLUSIVE,
        )
    double_processed = race_confirmer(finding, accepted)
    if double_processed is True:
        return ReplayResult(
            True,
            f"bounded {_BURST}-way concurrent burst and the in-scope read-back shows the operation "
            "durably applied more than once (check-then-act guard bypassed; no idempotency key or "
            "lock) — exploit reproduced.",
            outcome=ReplayOutcome.REPRODUCED,
        )
    if double_processed is False:
        return ReplayResult(
            None,
            f"bounded {_BURST}-way concurrent burst ({accepted} accepted); the in-scope read-back "
            "shows the operation applied once this run — a race was NOT deterministically reproduced. "
            "This is an inconclusive human-review lead, not evidence the race is absent.",
            outcome=ReplayOutcome.INCONCLUSIVE,
        )
    return ReplayResult(
        None,
        f"bounded {_BURST}-way concurrent burst ({accepted} accepted) but the durable "
        "double-processing state could not be confirmed by the read-back — inconclusive "
        "(human-review lead).",
        outcome=ReplayOutcome.INCONCLUSIVE,
    )
