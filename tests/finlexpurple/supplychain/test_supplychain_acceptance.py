"""Phase 13 §5a acceptance: a planted project exercises all four detections.

Builds a small project carrying (a) a known-vulnerable dependency, (b) a
hallucinated/non-existent package name, (c) a payment-SDK typosquat name, and
(d) a planted secret, then runs the module in online and offline modes and
confirms each issue is caught, normalized into a Finding, and labeled with the
mode it ran in.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from finlexpurple.supplychain.mode import ScanMode
from finlexpurple.supplychain.scanner import SupplyChainResult, scan_supplychain

_AWS = "AKIAIOSFODNN7EXAMPLE"  # documentation-style key, not a real secret

# (a) a real osv-scanner JSON for the known-vulnerable dependency.
_OSV_JSON = json.dumps(
    {
        "results": [
            {
                "source": {"path": "requirements.txt"},
                "packages": [
                    {
                        "package": {"name": "requests", "version": "2.19.0", "ecosystem": "PyPI"},
                        "vulnerabilities": [
                            {"id": "GHSA-x84v-xcm2-53pg", "summary": "vuln",
                             "database_specific": {"severity": "HIGH"}}
                        ],
                        "groups": [{"max_severity": "7.5"}],
                    }
                ],
            }
        ]
    }
)


@pytest.fixture
def planted_project(tmp_path: Path) -> Path:
    (tmp_path / "requirements.txt").write_text(
        # (a) vulnerable  (b) hallucinated  (c) payment typosquat
        "requests==2.19.0\nreqeusts-helper==9.9.9\nstripee==1.0\n",
        encoding="utf-8",
    )
    (tmp_path / "settings.py").write_text(f"AWS_KEY = '{_AWS}'\n", encoding="utf-8")  # (d) secret
    return tmp_path


def _classes(result: SupplyChainResult) -> set[str]:
    return {f.vulnerability_class for f in result.findings}


def test_online_mode_catches_all_four_and_labels_online(planted_project: Path) -> None:
    # Oracle: everything exists except the hallucinated package.
    oracle = lambda name, eco: name != "reqeusts-helper"
    result = scan_supplychain(
        planted_project,
        mode=ScanMode.ONLINE,
        existence_oracle=oracle,
        osv_runner=lambda args: (1, _OSV_JSON, ""),
        pip_audit_runner=lambda args: (0, "[]", ""),
    )
    classes = _classes(result)
    assert "vulnerable_dependency" in classes  # (a) wrapped scanner, normalized
    assert "hallucinated_dependency" in classes  # (b) original
    assert "payment_sdk_typosquat" in classes  # (c) original
    assert "exposed_secret" in classes  # (d) original

    # The hallucinated + typosquat findings are labeled online.
    originals = [f for f in result.findings if f.vulnerability_class in
                 {"hallucinated_dependency", "payment_sdk_typosquat"}]
    assert originals and all("mode=online" in f.expected_signal for f in originals)
    # The planted secret is redacted, never stored raw.
    secret = next(f for f in result.findings if f.vulnerability_class == "exposed_secret")
    assert _AWS not in (secret.response_snapshot or "")


def test_offline_mode_labels_lower_confidence_and_shows_feed_staleness(planted_project: Path) -> None:
    result = scan_supplychain(
        planted_project,
        mode=ScanMode.OFFLINE,
        osv_runner=lambda args: (1, _OSV_JSON, ""),
        pip_audit_runner=lambda args: (0, "[]", ""),
    )
    # Offline still catches the typosquat (heuristic) and the secret.
    typo = [f for f in result.findings if f.vulnerability_class == "payment_sdk_typosquat"]
    assert typo and all("mode=offline" in f.expected_signal for f in typo)
    assert all("confidence=low" in f.expected_signal for f in typo)
    # The report exposes feed staleness honestly.
    assert "offline feed last refreshed" in result.feed_status.summary()
