"""Payment-gateway / application-type fingerprinting for triage (Phase 19a; §7, §14).

Compass uses this to recognize which payment gateway or application type a target
uses and recommend the matching specialist agent. Matching is simple, local
substring detection over a corpus (the target URL, response headers, body, and
recon'd paths) — no LLM, no network of its own; the caller supplies the corpus.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class GatewayProfile:
    """A recognizable gateway/application type and the substrings that signal it."""

    name: str
    application_type: str  # ecommerce | banking | subscription | marketplace | crypto | lending | remittance
    signatures: tuple[str, ...]


# Pakistani + international gateways (§7) plus application-type markers for triage.
_PROFILES: tuple[GatewayProfile, ...] = (
    GatewayProfile("stripe", "ecommerce", ("js.stripe.com", "stripe.com", "payment_intent")),
    GatewayProfile("paypal", "ecommerce", ("paypal.com", "paypalobjects", "paypal-sdk")),
    GatewayProfile("adyen", "ecommerce", ("adyen.com", "checkoutshopper", "adyen")),
    GatewayProfile("razorpay", "ecommerce", ("razorpay.com", "razorpay")),
    GatewayProfile("jazzcash", "ecommerce", ("jazzcash", "sandbox.jazzcash")),
    GatewayProfile("easypaisa", "ecommerce", ("easypaisa", "easypay")),
    GatewayProfile("payfast", "ecommerce", ("payfast",)),
    GatewayProfile(
        "bank_gateway",
        "banking",
        ("netbanking", "corebanking", "internet-banking", "online-banking", "/ib/", "account/transfer"),
    ),
    GatewayProfile(
        "subscription_billing",
        "subscription",
        ("/subscription", "/billing", "recurring", "/plans", "chargebee", "recurly"),
    ),
)

# application type -> the specialist agent that handles it (full §14 roster).
_SPECIALIST = {
    "ecommerce": "cashier",
    "banking": "teller",
    "subscription": "ledger",
    "marketplace": "broker",
    "crypto": "vault",
    "lending": "underwriter",
    "remittance": "courier",
}

# Highest-risk first, so a target with mixed signals is routed to the safest handler.
_PRIORITY = ("banking", "crypto", "ecommerce", "subscription", "marketplace", "lending", "remittance")


def identify_gateways(corpus: str) -> list[GatewayProfile]:
    """Return every gateway/application profile whose signatures appear in ``corpus``."""

    lowered = corpus.lower()
    return [profile for profile in _PROFILES if any(sig.lower() in lowered for sig in profile.signatures)]


def recommend_specialist(gateways: list[GatewayProfile]) -> str | None:
    """Recommend the specialist agent for the detected gateways (highest-risk wins)."""

    types = {gateway.application_type for gateway in gateways}
    for application_type in _PRIORITY:
        if application_type in types:
            return _SPECIALIST[application_type]
    return None
