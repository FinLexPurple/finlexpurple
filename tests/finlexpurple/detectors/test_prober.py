"""Phase 10: the scope-safe HTTP prober."""

from __future__ import annotations

import pytest

from finlexpurple.detectors.prober import HttpProber
from finlexpurple.security.egress_policy import EgressBlockedError, EgressPolicy


def test_prober_blocks_out_of_scope_before_sending() -> None:
    prober = HttpProber(EgressPolicy.for_run(target_hosts=["127.0.0.1"]))
    with pytest.raises(EgressBlockedError):
        prober.request("GET", "https://evil.example.net/steal")


def test_prober_round_trips_against_a_local_server(vulnerable_server: str) -> None:
    prober = HttpProber(EgressPolicy.for_run(target_hosts=["127.0.0.1"]))
    resp = prober.request("GET", vulnerable_server + "/greet", params={"name": "x"})
    assert resp.status_code == 200
    assert "Hello x" in resp.text
    assert "content-type" in resp.headers  # headers are lowercased
