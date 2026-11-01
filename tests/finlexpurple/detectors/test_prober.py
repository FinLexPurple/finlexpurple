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


def test_prober_forwards_a_request_body(monkeypatch) -> None:
    # The additive `body` is forwarded to httpx as the raw request content, so a
    # POST forgery (e.g. a webhook callback) can carry a payload.
    import finlexpurple.detectors.prober as prober_mod

    captured: dict = {}

    class _Resp:
        status_code = 200
        text = "ok"

        def __init__(self) -> None:
            self.headers: dict[str, str] = {}

    class _Client:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def request(self, method, url, *, params=None, headers=None, content=None):
            captured["method"], captured["content"] = method, content
            return _Resp()

    monkeypatch.setattr(prober_mod.httpx, "Client", lambda **kwargs: _Client())
    prober = HttpProber(EgressPolicy.for_run(target_hosts=["127.0.0.1"]))
    resp = prober.request("POST", "http://127.0.0.1/webhook", body='{"status":"paid"}')
    assert resp.status_code == 200
    assert captured["method"] == "POST" and captured["content"] == '{"status":"paid"}'
