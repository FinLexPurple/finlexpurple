"""Phase 13: the supply-chain aggregator and manifest parsing."""

from __future__ import annotations

import json
from pathlib import Path

from finlexpurple.supplychain.mode import ScanMode
from finlexpurple.supplychain.scanner import read_dependencies, scan_supplychain


def test_read_dependencies_from_requirements_and_package_json(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text(
        "# comment\n-e .\nrequests==2.19.0\nFlask>=1.0  # inline\n", encoding="utf-8"
    )
    (tmp_path / "package.json").write_text(
        json.dumps({"dependencies": {"stripe": "^1.0"}, "devDependencies": {"jest": "^29"}}),
        encoding="utf-8",
    )
    deps = read_dependencies(tmp_path)
    assert ("requests", "PyPI") in deps
    assert ("flask", "PyPI") in deps
    assert ("stripe", "npm") in deps
    assert ("jest", "npm") in deps


def test_scan_warns_when_wrapped_tools_absent(tmp_path: Path) -> None:
    # No runners injected and neither binary is installed here -> honest warnings.
    (tmp_path / "requirements.txt").write_text("requests==2.19.0\n", encoding="utf-8")
    result = scan_supplychain(tmp_path, mode=ScanMode.OFFLINE)
    assert any("osv-scanner not installed" in w for w in result.warnings)
    assert any("pip-audit not installed" in w for w in result.warnings)
    assert result.feed_status is not None


def test_scan_aggregates_with_injected_runners(tmp_path: Path) -> None:
    (tmp_path / "requirements.txt").write_text("stripee==1.0\n", encoding="utf-8")
    osv_json = json.dumps(
        {
            "results": [
                {
                    "source": {"path": str(tmp_path)},
                    "packages": [
                        {
                            "package": {"name": "stripee", "version": "1.0", "ecosystem": "PyPI"},
                            "vulnerabilities": [{"id": "OSV-TEST-1", "summary": "x"}],
                            "groups": [{"max_severity": "5.0"}],
                        }
                    ],
                }
            ]
        }
    )
    result = scan_supplychain(
        tmp_path,
        mode=ScanMode.OFFLINE,
        osv_runner=lambda args: (1, osv_json, ""),
        pip_audit_runner=lambda args: (0, "[]", ""),
    )
    classes = {f.vulnerability_class for f in result.findings}
    assert "vulnerable_dependency" in classes  # from the wrapped scanner
    assert "payment_sdk_typosquat" in classes  # from our original detection
    assert result.warnings == []
