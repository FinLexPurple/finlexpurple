"""Unit 1.5: every payload's keys are allow-listed (envelope + props), no leakage."""

from __future__ import annotations

from finlexpurple.telemetry import allowlist, collector
from finlexpurple.telemetry.envelope import TELEMETRY_SCHEMA_VERSION

_UUID = "11111111-1111-4111-8111-111111111111"

# Keys that must NEVER appear in a payload (target / evidence / secrets), at the
# top level or inside props.
_FORBIDDEN = {"target", "url", "payload", "response", "response_snapshot", "body",
              "headers", "finding_id", "run_id", "api_key", "source", "hostname", "ip", "email"}


def _assert_clean(payload: dict) -> None:
    assert allowlist.disallowed_keys(payload) == set()          # subset of allow-list
    assert _FORBIDDEN.isdisjoint(payload)                        # no forbidden top-level keys
    props = payload.get("props")
    if isinstance(props, dict):
        assert _FORBIDDEN.isdisjoint(props)                     # nor inside props


def test_install_payload_is_the_envelope_with_empty_props() -> None:
    payload = collector.build_install_payload(_UUID)
    _assert_clean(payload)
    assert payload["schema_version"] == TELEMETRY_SCHEMA_VERSION
    assert payload["event"] == "install"
    assert payload["install_id"] == _UUID
    assert payload["props"] == {}
    # event + install_id stay top-level so the pre-0.4.0 counter still reads them.
    assert "event" in payload and "install_id" in payload


def test_scan_completed_payload_is_surfaces_and_bucketed_counts_only() -> None:
    payload = collector.build_scan_completed_payload(
        install_id=_UUID,
        web=True, mcp=False, deps=True, container=False,
        status_counts={"reported": 18, "verified": 4, "not_reproduced": 0},
    )
    _assert_clean(payload)
    assert payload["event"] == "scan_completed"
    props = payload["props"]
    assert props["web"] is True and props["mcp"] is False
    assert props["reported"] == "10-49"      # bucketed, never the raw 18
    assert props["verified"] == "1-9"
    assert props["not_reproduced"] == "0"
    assert payload["ts_day"].count("-") == 2  # YYYY-MM-DD, day granularity only


def test_bundle_payloads_carry_only_mode_and_result() -> None:
    created = collector.build_bundle_created_payload(install_id=_UUID, signed=True)
    _assert_clean(created)
    assert created["event"] == "bundle_created" and created["props"] == {"bundle_mode": "signed"}

    verified = collector.build_bundle_verified_payload(install_id=_UUID, passed=False)
    _assert_clean(verified)
    assert verified["event"] == "bundle_verified" and verified["props"] == {"verify_result": "fail"}


def test_feedback_payload_is_flat_and_has_no_ids_or_install_id() -> None:
    payload = collector.build_feedback_payload(
        run_rating="good", finding_mark="false-positive", vulnerability_class="sqli"
    )
    _assert_clean(payload)
    assert payload["event"] == "feedback"
    assert "run_id" not in payload and "finding_id" not in payload
    assert "install_id" not in payload          # feedback is never tied to an install


def test_allowlisted_drops_unknown_keys_top_level_and_in_props() -> None:
    cleaned = allowlist.allowlisted(
        {"event": "x", "url": "http://secret", "props": {"web": True, "api_key": "k"}}
    )
    assert cleaned == {"event": "x", "props": {"web": True}}


def test_disallowed_keys_names_bad_prop_keys() -> None:
    bad = allowlist.disallowed_keys({"event": "x", "props": {"leak": 1}})
    assert bad == {"props.leak"}
