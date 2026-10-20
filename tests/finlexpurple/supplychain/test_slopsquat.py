"""Phase 13: slopsquat detection, online vs offline, honestly labeled."""

from __future__ import annotations

from finlexpurple.supplychain import feeds
from finlexpurple.supplychain.mode import ScanMode
from finlexpurple.supplychain.slopsquat import check_dependencies


def test_online_oracle_flags_a_nonexistent_package_high_confidence() -> None:
    # Oracle says this invented name does not exist in the registry.
    oracle = lambda name, eco: name != "reqeusts-helper"
    findings = check_dependencies(
        [("requests", "PyPI"), ("reqeusts-helper", "PyPI")],
        mode=ScanMode.ONLINE,
        oracle=oracle,
    )
    assert len(findings) == 1
    f = findings[0]
    assert f.vulnerability_class == "hallucinated_dependency"
    assert "mode=online" in f.expected_signal
    assert "confidence=high" in f.expected_signal


def test_offline_flags_only_known_bad_at_low_confidence() -> None:
    bad = next(iter(feeds.KNOWN_BAD_PACKAGES))
    findings = check_dependencies(
        [(bad, "PyPI"), ("some-unknown-but-plausible-pkg", "PyPI")],
        mode=ScanMode.OFFLINE,
    )
    # Only the known-bad one is flagged; the plausible unknown is NOT overclaimed.
    assert len(findings) == 1
    assert "mode=offline" in findings[0].expected_signal
    assert "confidence=low" in findings[0].expected_signal


def test_offline_does_not_assert_nonexistence_without_a_live_source() -> None:
    findings = check_dependencies([("totally-made-up-xyz", "PyPI")], mode=ScanMode.OFFLINE)
    assert findings == []
