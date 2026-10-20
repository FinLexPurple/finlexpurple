"""Phase 13: secrets detection redacts the raw value, never stores it."""

from __future__ import annotations

from pathlib import Path

from finlexpurple.supplychain.secrets import scan_path, scan_text

_AWS = "AKIAIOSFODNN7EXAMPLE"  # documentation-style AWS key id (not a real secret)
_STRIPE = "sk_live_" + "a" * 30


def test_detects_aws_key_but_redacts_it() -> None:
    findings = scan_text(f"aws_key = {_AWS}", location="config.py")
    assert len(findings) == 1
    f = findings[0]
    assert f.vulnerability_class == "exposed_secret"
    # The raw secret must never appear in the finding anywhere.
    assert _AWS not in (f.response_snapshot or "")
    assert _AWS not in f.expected_signal
    assert _AWS not in f.payload
    assert "redacted" in (f.response_snapshot or "")


def test_detects_stripe_live_key_as_critical() -> None:
    from finlexpurple.detectors.schema import Severity

    findings = scan_text(f"STRIPE={_STRIPE}", location="e.env")
    assert findings and findings[0].severity is Severity.CRITICAL
    assert _STRIPE not in (findings[0].response_snapshot or "")


def test_clean_text_yields_nothing() -> None:
    assert scan_text("just some ordinary code = 1", location="x.py") == []


def test_scan_path_walks_tree_and_skips_vendor_dirs(tmp_path: Path) -> None:
    (tmp_path / "app.py").write_text(f"token = {_AWS}", encoding="utf-8")
    vendor = tmp_path / "node_modules"
    vendor.mkdir()
    (vendor / "lib.js").write_text(f"k = {_AWS}", encoding="utf-8")  # must be skipped

    findings = scan_path(tmp_path)
    assert len(findings) == 1
    assert findings[0].url.endswith("app.py:1")
