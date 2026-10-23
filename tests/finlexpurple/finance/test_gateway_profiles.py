"""Phase 19a: gateway fingerprinting and specialist recommendation."""

from __future__ import annotations

from finlexpurple.finance.gateway_profiles import identify_gateways, recommend_specialist


def test_ecommerce_gateway_recommends_cashier() -> None:
    gws = identify_gateways("<script src='https://js.stripe.com/v3'></script> payment_intent")
    assert "stripe" in {g.name for g in gws}
    assert recommend_specialist(gws) == "cashier"


def test_banking_markers_recommend_teller() -> None:
    gws = identify_gateways("https://bank.example/online-banking/account/transfer netbanking")
    assert recommend_specialist(gws) == "teller"


def test_subscription_markers_recommend_ledger() -> None:
    gws = identify_gateways("https://app.example/billing/plans recurring chargebee")
    assert recommend_specialist(gws) == "ledger"


def test_banking_wins_over_ecommerce_when_mixed() -> None:
    gws = identify_gateways("js.stripe.com and netbanking")  # both present
    assert recommend_specialist(gws) == "teller"  # highest-risk wins


def test_no_markers_recommends_nothing() -> None:
    assert recommend_specialist(identify_gateways("just a plain site")) is None
