"""Unit 1.3: the stable rule_id catalog and the severity -> SARIF level map."""

from __future__ import annotations

from finlexpurple.detectors.schema import Severity
from finlexpurple.reporting.rule_catalog import (
    RULE_CATALOG,
    SARIF_LEVELS,
    rule_record,
    sarif_level,
)


def test_rule_id_equals_its_key_for_every_entry() -> None:
    """The catalog key and the record's rule_id are the same frozen id."""

    for key, record in RULE_CATALOG.items():
        assert record.rule_id == key


def test_catalog_covers_the_core_classes() -> None:
    for rule_id in ("sqli", "idor", "price_tampering", "webhook_bypass", "vulnerable_dependency"):
        assert rule_id in RULE_CATALOG


def test_severity_maps_to_sarif_levels() -> None:
    assert sarif_level(Severity.CRITICAL) == "error"
    assert sarif_level(Severity.HIGH) == "error"
    assert sarif_level(Severity.MEDIUM) == "warning"
    assert sarif_level(Severity.LOW) == "note"
    assert sarif_level(Severity.INFO) == "note"
    assert set(SARIF_LEVELS) == {"error", "warning", "note"}


def test_unknown_class_gets_a_safe_fallback_record() -> None:
    record = rule_record("a_brand_new_class_without_an_entry")
    assert record.rule_id == "a_brand_new_class_without_an_entry"
    assert record.family == "unknown"
    assert record.default_severity is Severity.MEDIUM
