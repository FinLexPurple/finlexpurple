"""Phase 17: every payload's keys are a subset of the allow-list (no leakage)."""

from __future__ import annotations

from finlexpurple.telemetry import allowlist, collector

# Fields that must NEVER appear in a payload (target / evidence / secrets).
_FORBIDDEN = {"target", "url", "payload", "response", "response_snapshot", "body",
              "headers", "finding_id", "run_id", "api_key", "source", "hostname", "ip", "email"}


def _assert_clean(payload: dict) -> None:
    assert allowlist.disallowed_keys(payload) == set()          # subset of allow-list
    assert set(payload) <= allowlist.ALLOWED_FIELDS
    assert _FORBIDDEN.isdisjoint(payload)                        # no target/evidence/secret keys


def test_install_payload_is_just_event_and_random_id() -> None:
    payload = collector.build_install_payload("11111111-1111-4111-8111-111111111111")
    assert set(payload) == {"event", "install_id"}
    _assert_clean(payload)


def test_scan_summary_payload_is_counts_only() -> None:
    payload = collector.build_scan_summary_payload(
        total_findings=18, verified=4, verified_percent=22.2,
        severity_counts={"critical": 0, "high": 4, "medium": 2, "low": 6, "info": 6},
        vulnerability_classes=["sqli", "ssrf", "sqli", "idor", "xss"],
    )
    _assert_clean(payload)
    assert payload["verified"] == 4
    assert payload["vulnerability_classes"] == ["idor", "sqli", "ssrf", "xss"]  # deduped, sorted


def test_feedback_payload_has_no_ids() -> None:
    payload = collector.build_feedback_payload(
        run_rating="good", finding_mark="false-positive", vulnerability_class="sqli"
    )
    _assert_clean(payload)
    assert "run_id" not in payload and "finding_id" not in payload


def test_allowlisted_drops_unknown_keys() -> None:
    cleaned = allowlist.allowlisted({"event": "x", "url": "http://secret", "api_key": "k"})
    assert cleaned == {"event": "x"}
