"""Cross-platform smoke tests that use real host detection, without hardware mocks."""

from __future__ import annotations

from pathlib import Path

from typer.testing import CliRunner

from finlexpurple.cli import app
from finlexpurple.hardware.detect import detect_hardware
from finlexpurple.hardware.tiers import ModelTier, recommend_tier


def test_real_hardware_detection_returns_plausible_facts() -> None:
    facts = detect_hardware()

    assert 0 < facts.total_ram_gb < 4096
    assert facts.free_disk_gb >= 0
    assert facts.gpu_kind in {"none", "nvidia", "amd", "apple_silicon"}
    if facts.gpu_memory_gb is not None:
        assert 0 < facts.gpu_memory_gb < 4096
    assert facts.model_directory
    assert facts.disk_checked_path.exists()


def test_setup_scripted_against_real_hardware(tmp_path: Path, monkeypatch) -> None:
    facts = detect_hardware()
    tier = recommend_tier(facts)
    monkeypatch.chdir(tmp_path)
    inputs = "1\n1\nn\n" if tier is ModelTier.LOCAL_8B_HYBRID else "1\n1\n"

    result = CliRunner().invoke(app, ["setup"], input=inputs)

    assert result.exit_code == 0, result.output
    assert "Total system RAM:" in result.output
    assert "Saved MODEL_TIER=" in result.output
    assert (tmp_path / ".env").is_file()
