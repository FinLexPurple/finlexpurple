"""Operator-oracle read-back confirmers — the single source of truth.

A verification confirmer answers one question honestly: did the active probe
leave a *durable* effect on the target? It answers only by reading in-scope state
back through the egress-checked prober — never by trusting a lab-computed flag and
never by synthesizing a signal. Each returns ``True`` only when the durable effect
is genuinely present, ``False`` when the read succeeds and it is not, and ``None``
when the read cannot be made (so the finding stays INCONCLUSIVE / ``reported``,
never VERIFIED).

These were built for the CLI ``scan`` / ``run`` paths; they live here so the
interactive chat scan path (``tui.scan_context``) wires the *same* read-back logic
rather than a divergent copy — a copy is exactly where a VERIFIED verdict could
drift. Most read the durable effect from a SEPARATE, operator-provided
order-status oracle URL (``--order-status-url`` / ``FLP_ORDER_STATUS_URL``); absent
one, a real read-back is impossible and the finding stays INCONCLUSIVE.
"""

from __future__ import annotations

import re

from finlexpurple.detectors.prober import Prober
from finlexpurple.detectors.schema import Finding
from finlexpurple.verifier.replay.coupon_abuse_replay import CouponConfirmer
from finlexpurple.verifier.replay.payment_status_trust_replay import PaymentStatusConfirmer
from finlexpurple.verifier.replay.price_tampering_replay import ChargeConfirmer
from finlexpurple.verifier.replay.race_condition_replay import RaceConfirmer
from finlexpurple.verifier.replay.refund_abuse_replay import RefundConfirmer
from finlexpurple.verifier.replay.webhook_bypass_replay import SettlementConfirmer

# Machine-readable tokens the refund-status oracle exposes: the order's durable
# amount paid and refunded total. The tool parses BOTH and owns the over-refund
# verdict (refunded > paid) itself — it never trusts a lab-computed flag.
_REFUND_AMOUNT_RE = re.compile(r'data-refund-amount="([0-9]+(?:\.[0-9]+)?)"')
_REFUND_REFUNDED_RE = re.compile(r'data-refund-refunded="([0-9]+(?:\.[0-9]+)?)"')

# Machine-readable token the race oracle exposes: the number of times the
# single-use operation was durably applied. The tool parses it and owns the
# double-processing verdict (applied >= 2) itself — it never trusts a lab flag.
_RACE_APPLIED_RE = re.compile(r'data-race-applied="([0-9]+)"')


def charge_confirmer_for(prober: Prober) -> ChargeConfirmer:
    """Price-tampering read-back: re-read the resource and see if the tampered value persisted.

    A genuine in-scope read-back via the egress-checked prober: re-read the
    resource (without the tampered input) and check whether the manipulated amount
    is present. Never synthesizes a charge — if the read cannot be made it returns
    ``None`` so the finding stays ``reported``.
    """

    def confirm(finding: Finding, value: str) -> bool | None:
        try:
            return value in prober.request("GET", finding.url).text
        except Exception:  # noqa: BLE001 - any read-back failure = unconfirmable -> stays reported
            return None

    return confirm


def settlement_confirmer_for(prober: Prober, order_status_url: str | None) -> SettlementConfirmer:
    """Webhook-bypass settlement read-back from an operator-provided order-status oracle.

    The forged callback's durable effect — did the order flip to paid? — is read
    from a SEPARATE, operator-provided order-status URL, never by re-reading the
    webhook endpoint (a webhook URL does not expose order state). Without an oracle
    URL it returns ``None`` (stays INCONCLUSIVE). With one, it substitutes the
    forged sentinel order id for a literal ``{order_id}`` placeholder and GETs that
    URL through the egress-checked prober (in-scope only; an out-of-scope URL is
    blocked before any socket opens), returning ``True`` only when the oracle
    genuinely shows that order paid. A paid signal is never synthesized.
    """

    from finlexpurple.finance.payment_tests import webhook_bypass

    def confirm(finding: Finding) -> bool | None:
        del finding  # the forgery targets a fixed sentinel order; the oracle URL addresses it
        if not order_status_url:
            return None
        url = order_status_url.replace("{order_id}", webhook_bypass.FORGED_ORDER_ID)
        try:
            text = prober.request("GET", url).text
        except Exception:  # noqa: BLE001 - any read-back failure = unconfirmable -> inconclusive
            return None
        return webhook_bypass.PAID_MARKER in text and webhook_bypass.FORGED_ORDER_ID in text

    return confirm


def coupon_confirmer_for(prober: Prober, order_status_url: str | None) -> CouponConfirmer:
    """Coupon-abuse read-back: did the illegitimate discount persist on the cart order?

    Read from the SAME operator-provided order-status oracle, pointed at the cart
    order id. Without an oracle URL it returns ``None`` (stays INCONCLUSIVE). With
    one, it GETs the oracle through the egress-checked prober and returns ``True``
    only when the applied coupon code is genuinely recorded on the persisted order.
    A discount signal is never synthesized.
    """

    from finlexpurple.finance.payment_tests import coupon_abuse

    def confirm(finding: Finding, code: str) -> bool | None:
        del finding  # the coupon targets the fixed cart order; the oracle URL addresses it
        if not order_status_url:
            return None
        url = order_status_url.replace("{order_id}", coupon_abuse.CART_ORDER_ID)
        try:
            text = prober.request("GET", url).text
        except Exception:  # noqa: BLE001 - any read-back failure = unconfirmable -> inconclusive
            return None
        return code in text

    return confirm


def payment_status_confirmer_for(
    prober: Prober, order_status_url: str | None
) -> PaymentStatusConfirmer:
    """Payment-status read-back: is the order durably marked (e.g. paid) without settlement?

    Read from the SAME operator-provided order-status oracle, pointed at the
    dedicated status order id. Without an oracle URL it returns ``None`` (stays
    INCONCLUSIVE). With one, it returns ``True`` only when the order genuinely
    shows that status. A paid signal is never synthesized.
    """

    from finlexpurple.finance.payment_tests import payment_status_trust

    def confirm(finding: Finding, status: str) -> bool | None:
        del finding  # the set targets the fixed status order; the oracle URL addresses it
        if not order_status_url:
            return None
        url = order_status_url.replace("{order_id}", payment_status_trust.STATUS_ORDER_ID)
        try:
            text = prober.request("GET", url).text
        except Exception:  # noqa: BLE001 - any read-back failure = unconfirmable -> inconclusive
            return None
        return status in text and payment_status_trust.STATUS_ORDER_ID in text

    return confirm


def refund_confirmer_for(prober: Prober, order_status_url: str | None) -> RefundConfirmer:
    """Over-refund read-back: does the order's refunded total exceed the amount paid?

    Read from the SAME operator-provided order-status oracle, pointed at the
    dedicated refund order id. Without an oracle URL it returns ``None`` (stays
    INCONCLUSIVE). With one, it parses the durable ``amount`` and ``refunded``
    tokens and returns ``True`` only when ``refunded > amount`` (a durable
    over-refund). The tool, not the lab, owns the comparison; an over-refund signal
    is never synthesized.
    """

    from finlexpurple.finance.payment_tests import refund_abuse

    def confirm(finding: Finding, amount: str) -> bool | None:
        del finding, amount  # the verdict compares durable refunded vs paid, not the requested value
        if not order_status_url:
            return None
        url = order_status_url.replace("{order_id}", refund_abuse.REFUND_ORDER_ID)
        try:
            text = prober.request("GET", url).text
        except Exception:  # noqa: BLE001 - any read-back failure = unconfirmable -> inconclusive
            return None
        if refund_abuse.REFUND_ORDER_ID not in text:
            return None
        paid_match = _REFUND_AMOUNT_RE.search(text)
        refunded_match = _REFUND_REFUNDED_RE.search(text)
        if paid_match is None or refunded_match is None:
            return None
        try:
            return float(refunded_match.group(1)) > float(paid_match.group(1))
        except ValueError:  # non-numeric durable state -> unconfirmable
            return None

    return confirm


def race_confirmer_for(prober: Prober, order_status_url: str | None) -> RaceConfirmer:
    """Double-processing read-back: was the single-use operation applied more than once?

    Read from the SAME operator-provided order-status oracle, pointed at the
    dedicated voucher order id. Without an oracle URL it returns ``None`` (stays
    INCONCLUSIVE). With one, it parses the durable ``applied`` count and returns
    ``True`` only when ``applied >= 2`` (a durable double-processing). The tool, not
    the lab, owns the comparison; a double-processing signal is never synthesized,
    and a genuine race that applied once this run honestly returns ``False`` ->
    INCONCLUSIVE.
    """

    from finlexpurple.finance.payment_tests import race_condition

    def confirm(finding: Finding, accepted: int) -> bool | None:
        del finding, accepted  # the verdict reads durable applied-count, not the burst's accept count
        if not order_status_url:
            return None
        url = order_status_url.replace("{order_id}", race_condition.RACE_ORDER_ID)
        try:
            text = prober.request("GET", url).text
        except Exception:  # noqa: BLE001 - any read-back failure = unconfirmable -> inconclusive
            return None
        if race_condition.RACE_ORDER_ID not in text:
            return None
        applied_match = _RACE_APPLIED_RE.search(text)
        if applied_match is None:
            return None
        return int(applied_match.group(1)) >= 2

    return confirm
