"""Unit 2.1: order-IDOR active capture end-to-end (login -> two-session read -> verify)
plus the FLP_IDOR_IDENTITIES config loader."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from finlexpurple.detectors.prober import ProbeResponse
from finlexpurple.detectors.schema import FindingStatus
from finlexpurple.finance import idor_identities
from finlexpurple.finance.payment_tests import order_idor

_ALICE_BODY = '{"id": "ord-alice-0001", "owner": "alice", "status": "paid"}'
_IDENTITIES = idor_identities.IdorIdentities(
    login_path="/login",
    owner=idor_identities.IdorIdentity(user="alice", order_path="/account/orders/ord-alice-0001"),
    other=idor_identities.IdorIdentity(user="bob"),
)


class _LabProber:
    """A fake of the lab's Scope-3 surface: /login sets a session cookie; the
    account-order resource either leaks cross-account (vulnerable) or is scoped."""

    def __init__(self, *, leak: bool) -> None:
        self._leak = leak

    def request(self, method, url, *, params=None, headers=None, body=None) -> ProbeResponse:
        if url.endswith("/login"):
            user = (params or {}).get("user")
            if user in ("alice", "bob"):
                return ProbeResponse(status_code=200,
                                     headers={"set-cookie": f"session={user}; HttpOnly; Path=/"}, text="{}")
            return ProbeResponse(status_code=401, headers={}, text="")
        if "/account/orders/" in url:
            cookie = (headers or {}).get("Cookie", "")
            if not cookie.startswith("session="):
                return ProbeResponse(status_code=401, headers={}, text="")  # auth required
            who = cookie.split("=", 1)[1]
            if self._leak or who == "alice":
                return ProbeResponse(status_code=200, headers={}, text=_ALICE_BODY)
            return ProbeResponse(status_code=403, headers={}, text="")  # scoped: non-owner denied
        return ProbeResponse(status_code=404, headers={}, text="")


def test_capture_reaches_verified_on_a_vulnerable_target() -> None:
    findings = order_idor.run_order_idor(
        "http://lab.invalid", agent="cashier", prober=_LabProber(leak=True), identities=_IDENTITIES,
    )
    assert len(findings) == 1
    assert findings[0].vulnerability_class == "order_idor"
    assert findings[0].status is FindingStatus.VERIFIED
    assert findings[0].url == "http://lab.invalid/account/orders/ord-alice-0001"


def test_capture_is_not_reproduced_on_a_scoped_target() -> None:
    findings = order_idor.run_order_idor(
        "http://lab.invalid", agent="cashier", prober=_LabProber(leak=False), identities=_IDENTITIES,
    )
    assert len(findings) == 1 and findings[0].status is FindingStatus.NOT_REPRODUCED


def test_no_identities_runs_nothing() -> None:
    assert order_idor.run_order_idor(
        "http://lab.invalid", agent="cashier", prober=_LabProber(leak=True), identities=None,
    ) == []


def test_login_failure_yields_no_finding() -> None:
    class _NoLogin(_LabProber):
        def request(self, method, url, *, params=None, headers=None, body=None):
            if url.endswith("/login"):
                return ProbeResponse(status_code=500, headers={}, text="")
            return super().request(method, url, params=params, headers=headers, body=body)

    assert order_idor.run_order_idor(
        "http://lab.invalid", agent="cashier", prober=_NoLogin(leak=True), identities=_IDENTITIES,
    ) == []


# --- config loader ------------------------------------------------------------


def test_load_identities_unset_is_none() -> None:
    assert idor_identities.load_identities(env={}) is None


def test_load_identities_parses_a_valid_file(tmp_path: Path) -> None:
    path = tmp_path / "idor.json"
    path.write_text(json.dumps({
        "login_path": "/login",
        "owner": {"user": "alice", "order_path": "/account/orders/ord-alice-0001"},
        "other": {"user": "bob"},
    }), encoding="utf-8")
    loaded = idor_identities.load_identities(env={idor_identities.ENV_IDOR_IDENTITIES: str(path)})
    assert loaded == _IDENTITIES


def test_load_identities_rejects_a_missing_field(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"login_path": "/login", "owner": {"user": "alice"},
                                "other": {"user": "bob"}}), encoding="utf-8")
    with pytest.raises(idor_identities.IdorConfigError, match="order_path"):
        idor_identities.load_identities(env={idor_identities.ENV_IDOR_IDENTITIES: str(path)})


def test_load_identities_rejects_unreadable_path() -> None:
    with pytest.raises(idor_identities.IdorConfigError, match="cannot read"):
        idor_identities.load_identities(env={idor_identities.ENV_IDOR_IDENTITIES: "/no/such/idor.json"})
