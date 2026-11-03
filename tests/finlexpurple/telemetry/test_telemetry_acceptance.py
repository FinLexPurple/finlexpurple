"""Phase 17 §5a acceptance: the four telemetry checklist items.

1. telemetry show output keys are a subset of the allow-list.
2. with TELEMETRY_ENABLED=false (default), the sender makes no network call.
3. no target/request/response/source/key ever appears in a payload.
4. the install payload is a single random local UUID with no other identifier.
"""

from __future__ import annotations

import uuid

from finlexpurple.config import Config
from finlexpurple.telemetry import allowlist, collector
from finlexpurple.telemetry.cli_commands import preview_payloads
from finlexpurple.telemetry.sender import send


def test_item1_show_preview_keys_are_subset_of_allowlist() -> None:
    for payload in preview_payloads("11111111-1111-4111-8111-111111111111").values():
        assert set(payload) <= allowlist.ALLOWED_FIELDS


def test_item2_disabled_default_sends_nothing() -> None:
    calls: list = []
    result = send(
        {"event": "install", "install_id": "x"},
        config=Config.model_construct(telemetry_enabled=False, telemetry_endpoint="https://x.invalid"),
        transport=lambda url, payload: calls.append(1) or 200,
    )
    assert result.sent is False and calls == []


def test_item3_no_target_or_evidence_in_a_realistic_scan_payload() -> None:
    # A realistic scan: surfaces ran, 18 findings, 4 verified.
    payload = collector.build_scan_completed_payload(
        install_id="11111111-1111-4111-8111-111111111111",
        web=True, mcp=False, deps=True, container=False,
        status_counts={"reported": 18, "verified": 4, "inconclusive": 2},
    )
    serialized = str(payload)
    for leak in ("127.0.0.1", "/login", "/lookup", "http://", "q=", "api_key", "password", "SELECT"):
        assert leak not in serialized
    assert allowlist.disallowed_keys(payload) == set()


def test_item4_install_payload_is_envelope_plus_one_random_uuid() -> None:
    payload = collector.build_install_payload("22222222-2222-4222-8222-222222222222")
    assert allowlist.disallowed_keys(payload) == set()
    assert payload["event"] == "install" and payload["props"] == {}
    assert uuid.UUID(payload["install_id"]).version == 4
