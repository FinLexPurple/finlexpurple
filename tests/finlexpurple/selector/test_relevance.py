"""Decision 1: deterministic relevance selection over the fixed registry."""

from __future__ import annotations

from finlexpurple.agents.registry import get_agent
from finlexpurple.selector.relevance import relevant_agents

_ENDPOINTS = [object()]  # presence only; relevance does not inspect their shape here


def test_ecommerce_target_selects_hunter_then_cashier() -> None:
    corpus = "GET /checkout\nscript src=js.stripe.com/v3 payment_intent"
    assert relevant_agents(corpus, _ENDPOINTS) == ["hunter", "cashier"]


def test_banking_target_selects_hunter_then_teller() -> None:
    corpus = "GET /ib/account/transfer\ncorebanking netbanking portal"
    assert relevant_agents(corpus, _ENDPOINTS) == ["hunter", "teller"]


def test_plain_site_with_endpoints_selects_web_only() -> None:
    assert relevant_agents("GET /about\nServer: nginx", _ENDPOINTS) == ["hunter"]


def test_no_endpoints_no_gateway_selects_nothing() -> None:
    assert relevant_agents("Server: nginx", []) == []


def test_every_selected_name_is_registered() -> None:
    corpus = "razorpay checkout /order?id=1"
    for name in relevant_agents(corpus, _ENDPOINTS):
        assert get_agent(name) is not None
