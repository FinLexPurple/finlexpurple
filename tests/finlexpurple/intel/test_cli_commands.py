"""Decision 2: intel show/pull/contribute backing logic + command wiring."""

from __future__ import annotations

import json

from typer.testing import CliRunner

from finlexpurple.detectors.schema import Finding, Severity
from finlexpurple.intel import cli_commands as ic
from finlexpurple.intel.pack import record_content_hash

runner = CliRunner()


def test_active_pack_falls_back_to_baseline(tmp_path) -> None:
    pack, source = ic.active_pack(tmp_path / "empty-cache")
    assert "baseline" in source
    assert len(pack.patterns) >= 1


def test_active_pack_prefers_valid_cache(tmp_path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    rec = {
        "fingerprint": "shop", "ordered_agents": ["hunter"], "reproduced_strategy": "reorder",
        "provenance": "lab",
        "content_hash": record_content_hash(fingerprint="shop", ordered_agents=["hunter"],
                                             reproduced_strategy="reorder", provenance="lab"),
    }
    (cache / "pack.json").write_text(json.dumps({
        "manifest": {"version": "cached-1", "schema_version": 1, "min_client_version": "0.3.0",
                     "created": "2026-11-01T00:00:00Z", "files": [], "previous_version": None,
                     "signature_ref": None},
        "patterns": [rec],
    }), encoding="utf-8")
    pack, source = ic.active_pack(cache)
    assert "cached" in source and pack.manifest.version == "cached-1"


def test_pull_wires_the_baked_channel(monkeypatch, tmp_path) -> None:
    from finlexpurple.intel import config

    captured = {}

    def fake_fetch(pack_url, signature_url, **kwargs):
        captured["pack_url"] = pack_url
        captured["kwargs"] = kwargs
        from finlexpurple.intel.download import DownloadResult
        return DownloadResult(True, tmp_path / "pack.json", "v1", "verified and cached")

    monkeypatch.setattr(ic, "fetch_and_cache", fake_fetch)
    message = ic.pull_text(tmp_path, allow_rollback=False, env={})
    assert "pull: ok" in message
    assert captured["pack_url"] == config.DEFAULT_PACKS_URL
    identity = captured["kwargs"]["expected_identity"]
    assert identity.identity_regexp == config.DEFAULT_PINNED_IDENTITY_REGEXP  # baked regexp pin
    assert captured["kwargs"]["expected_sha256"] is None  # no extra pin out of the box


def test_pull_fails_closed_when_identity_cleared() -> None:
    from finlexpurple.intel import config

    message = ic.pull_text(ic.default_cache_dir(), allow_rollback=False, env={config.ENV_IDENTITY: ""})
    assert "pull: refused" in message and "fail-closed" in message


def test_contribution_text_is_categorical_only(tmp_path) -> None:
    finding = Finding.new(vulnerability_class="price_tampering", method="GET",
                          url="https://shop.example/checkout?price=0.01", payload="price=0.01",
                          severity=Severity.HIGH)
    report = tmp_path / "report.json"
    report.write_text(json.dumps({"findings": [finding.to_dict()]}), encoding="utf-8")
    diff = ic.contribution_text(report, technology="stripe")
    assert "price_tampering" in diff
    assert "shop.example" not in diff and "price=0.01" not in diff  # no url/payload leak


def test_intel_show_command_runs() -> None:
    result = runner.invoke(ic.intel_app, ["show"])
    assert result.exit_code == 0
    assert "Active intelligence pack" in result.output
    assert "advisory-only" in result.output
