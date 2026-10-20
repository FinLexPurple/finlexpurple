"""Shipped offline data and feed-staleness reporting (Phase 13; §25, §18 #9/#10).

When air-gapped, the slopsquat/typosquat checks fall back to these shipped lists
and the report must show how stale the data is (§25). The *distribution,
signing, and refresh* of this data are explicitly open items (§18 #9 and #10),
so the lists below are a **provisional seed**, not an authoritative feed, and
the staleness report says so. Nothing here claims coverage the data cannot
support.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date

# PROVISIONAL: when this shipped data was last curated. A real build refreshes
# this via the (unspecified, §18 #9) `feeds update` mechanism.
FEED_LAST_REFRESHED = date(2026, 10, 20)
_STALE_AFTER_DAYS = 30

# Legitimate payment-SDK package names typosquats imitate (Differentiator 7).
# Seed set across PyPI/npm; flagged provisional pending the §18 #10 data source.
KNOWN_PAYMENT_SDKS: frozenset[str] = frozenset(
    {
        "stripe",
        "braintree",
        "square",
        "paypalrestsdk",
        "paypalhttp",
        "razorpay",
        "adyen",
        "plaid",
        "paysafe",
        "jazzcash",
        "easypaisa",
        "payfast",
        "authorizenet",
    }
)

# A small offline allow-list of packages known to exist (slopsquat offline mode).
KNOWN_GOOD_PACKAGES: frozenset[str] = frozenset(
    {
        "requests",
        "flask",
        "django",
        "numpy",
        "pandas",
        "httpx",
        "pydantic",
        "stripe",
        "boto3",
        "sqlalchemy",
    }
)

# Names shipped as known-bad (hallucinated or attacker-registered) for offline mode.
KNOWN_BAD_PACKAGES: frozenset[str] = frozenset(
    {
        "requirements-txt",
        "python-sqlite",
        "stripe-python-sdk",
        "easypaisa-sdk",
        "jazzcash-pay",
    }
)


@dataclass(frozen=True)
class FeedStatus:
    """How fresh the shipped offline data is, reported honestly."""

    last_refreshed: date
    age_days: int
    is_stale: bool
    note: str

    def summary(self) -> str:
        state = "STALE" if self.is_stale else "current"
        return (
            f"offline feed last refreshed {self.last_refreshed.isoformat()} "
            f"({self.age_days} days ago, {state}). {self.note}"
        )


def current_feed_status(today: date | None = None) -> FeedStatus:
    """Return the staleness of the shipped offline data as of ``today``."""

    now = today or date.today()
    age = (now - FEED_LAST_REFRESHED).days
    return FeedStatus(
        last_refreshed=FEED_LAST_REFRESHED,
        age_days=age,
        is_stale=age > _STALE_AFTER_DAYS,
        note="Provisional shipped seed data (§18 items 9/10 open); refresh online for live coverage.",
    )
