"""Phase 13: payment-SDK typosquat detection, online vs offline."""

from __future__ import annotations

from finlexpurple.supplychain.mode import ScanMode
from finlexpurple.supplychain.typosquat import check_dependencies, levenshtein


def test_levenshtein_basic() -> None:
    assert levenshtein("stripe", "stripe") == 0
    assert levenshtein("stripe", "stripee") == 1
    assert levenshtein("stripe", "strlpe") == 1


def test_exact_payment_sdk_is_not_flagged() -> None:
    assert check_dependencies([("stripe", "PyPI")], mode=ScanMode.OFFLINE) == []


def test_near_miss_is_flagged_offline_low_confidence() -> None:
    findings = check_dependencies([("stripee", "PyPI")], mode=ScanMode.OFFLINE)
    assert len(findings) == 1
    f = findings[0]
    assert f.vulnerability_class == "payment_sdk_typosquat"
    assert "mode=offline" in f.expected_signal
    assert "confidence=low" in f.expected_signal
    assert "stripe" in f.expected_signal


def test_online_registered_impostor_is_high_confidence() -> None:
    findings = check_dependencies(
        [("jazzcashh", "PyPI")],  # near "jazzcash"
        mode=ScanMode.ONLINE,
        oracle=lambda name, eco: True,  # the impostor is actually registered
    )
    assert len(findings) == 1
    assert "mode=online" in findings[0].expected_signal
    assert "confidence=high" in findings[0].expected_signal


def test_unrelated_package_is_not_flagged() -> None:
    assert check_dependencies([("numpy", "PyPI")], mode=ScanMode.OFFLINE) == []
