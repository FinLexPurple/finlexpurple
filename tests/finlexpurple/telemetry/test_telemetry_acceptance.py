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
    # Build from the real 0.3.0-style finding set (sqli x3, ssrf, idor, xss, misconfig).
    payload = collector.build_scan_summary_payload(
        total_findings=18, verified=4, verified_percent=22.2,
        severity_counts={"critical": 0, "high": 4, "medium": 2, "low": 6, "info": 6},
        vulnerability_classes=["sqli", "ssrf", "sqli", "sqli", "idor", "xss"] + ["generic_misconfig"] * 12,
    )
    serialized = str(payload)
    for leak in ("127.0.0.1", "/login", "/lookup", "http://", "q=", "api_key", "password", "SELECT"):
        assert leak not in serialized
    assert set(payload) <= allowlist.ALLOWED_FIELDS


def test_item4_install_payload_is_one_random_uuid_only() -> None:
    payload = collector.build_install_payload("22222222-2222-4222-8222-222222222222")
    assert set(payload) == {"event", "install_id"}
    assert uuid.UUID(payload["install_id"]).version == 4
