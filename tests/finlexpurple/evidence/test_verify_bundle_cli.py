"""Phase 12 §5a acceptance: `finlexpurple verify-bundle` standalone and offline.

Builds a bundle for a verified finding, writes it to a file, and re-verifies it
through the real CLI command with nothing else — no scan, no network — proving a
third party can independently confirm the bundle, and that any alteration is
caught.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

from typer.testing import CliRunner

from finlexpurple.cli import app
from finlexpurple.detectors.schema import Finding, FindingStatus
from finlexpurple.evidence.bundle import build_bundle, dumps_bundle

runner = CliRunner()
_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def _write_bundle(tmp_path: Path) -> tuple[Path, str]:
    finding = Finding.new(
        vulnerability_class="sqli",
        method="GET",
        url="http://t.invalid/search",
        payload="q='",
        response_snapshot="You have an error in your SQL syntax",
    )
    finding.status = FindingStatus.VERIFIED
    finding.verification_log = "re-executed the payload; SQL error signature reproduced."
    bundle = build_bundle(finding)
    path = tmp_path / "finding.bundle.json"
    path.write_text(dumps_bundle(bundle), encoding="utf-8")
    return path, bundle["content_hash"]


def test_verify_bundle_passes_for_an_untouched_bundle(tmp_path: Path) -> None:
    path, _ = _write_bundle(tmp_path)
    result = runner.invoke(app, ["verify-bundle", str(path)])
    assert result.exit_code == 0
    assert "OK: bundle verified." in _ANSI.sub("", result.stdout)


def test_verify_bundle_checks_the_expected_hash_chain(tmp_path: Path) -> None:
    path, content_hash = _write_bundle(tmp_path)
    result = runner.invoke(app, ["verify-bundle", str(path), "--expected-hash", content_hash])
    assert result.exit_code == 0
    assert "matches the expected hash" in _ANSI.sub("", result.stdout)


def test_verify_bundle_detects_tampering(tmp_path: Path) -> None:
    path, _ = _write_bundle(tmp_path)
    bundle = json.loads(path.read_text(encoding="utf-8"))
    bundle["payload"]["finding"]["url"] = "http://attacker.invalid/x"  # alter evidence
    path.write_text(json.dumps(bundle), encoding="utf-8")

    result = runner.invoke(app, ["verify-bundle", str(path)])
    assert result.exit_code == 1
    assert "HASH MISMATCH" in _ANSI.sub("", result.output)


def test_verify_bundle_rejects_a_non_bundle_file(tmp_path: Path) -> None:
    path = tmp_path / "junk.json"
    path.write_text("not a bundle", encoding="utf-8")
    result = runner.invoke(app, ["verify-bundle", str(path)])
    assert result.exit_code == 2


def test_verify_bundle_errors_clearly_on_a_missing_file(tmp_path: Path) -> None:
    result = runner.invoke(app, ["verify-bundle", str(tmp_path / "nope.json")])
    assert result.exit_code == 2
