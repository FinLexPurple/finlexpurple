"""Interactive setup wizard tests with synthetic hardware facts."""

from __future__ import annotations

from pathlib import Path

import pytest
from typer.testing import CliRunner

from finlexpurple.cli import app
from finlexpurple.config import LLMProvider
from finlexpurple.hardware import wizard
from finlexpurple.hardware.detect import HardwareFacts
from finlexpurple.hardware.tiers import ModelTier

runner = CliRunner()


@pytest.mark.parametrize(
    ("tier", "provider", "compatible"),
    [
        (tier, provider, (tier is ModelTier.CLOUD) == (provider is not LLMProvider.OLLAMA))
        for tier in ModelTier
        for provider in LLMProvider
    ],
)
def test_every_tier_provider_pairing(
    tier: ModelTier, provider: LLMProvider, compatible: bool
) -> None:
    assert (wizard._provider_incompatibility(tier, provider) is None) is compatible


@pytest.mark.parametrize(
    ("inputs", "gpu_kind", "gpu_memory", "expected_message"),
    [
        ("1\n1\n2\n", "none", None, "cloud tier requires a cloud provider"),
        (
            "1\n2\n1\n",
            "nvidia",
            24.0,
            "local-30b tier requires Ollama",
        ),
        (
            "1\n2\n1\n",
            "nvidia",
            12.0,
            "local-8b-hybrid tier currently requires Ollama",
        ),
        (
            "2\ny\n2\n1\n",
            "none",
            None,
            "local-3b-triage tier requires Ollama",
        ),
    ],
)
def test_provider_rejection_reprompts_with_clear_message(
    monkeypatch,
    tmp_path,
    inputs: str,
    gpu_kind: str,
    gpu_memory: float | None,
    expected_message: str,
) -> None:
    hardware = facts(ram=8 if gpu_kind == "none" else 32, gpu_kind=gpu_kind, gpu_memory=gpu_memory)
    result = run_setup(monkeypatch, tmp_path, inputs, hardware)

    assert result.exit_code == 0, result.output
    assert expected_message in result.output
    assert "Saved MODEL_TIER=" in result.output


def facts(
    ram: float = 16,
    free_disk: float = 30,
    gpu_kind: str = "none",
    gpu_memory: float | None = None,
) -> HardwareFacts:
    return HardwareFacts(
        total_ram_gb=ram,
        model_directory=Path("/synthetic/models"),
        disk_checked_path=Path("/synthetic"),
        free_disk_gb=free_disk,
        gpu_kind=gpu_kind,
        gpu_name="Synthetic GPU" if gpu_memory is not None else None,
        gpu_memory_gb=gpu_memory,
        operating_system="Synthetic OS",
    )


def run_setup(monkeypatch, tmp_path: Path, inputs: str, hardware: HardwareFacts):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr(wizard, "detect_hardware", lambda: hardware)
    return runner.invoke(app, ["setup"], input=inputs)


def test_no_gpu_low_ram_only_offers_cloud_and_persists_choices(monkeypatch, tmp_path) -> None:
    result = run_setup(monkeypatch, tmp_path, "1\n2\n", facts(ram=7.9))

    assert result.exit_code == 0, result.output
    assert "local-3b-triage" not in result.output
    assert "Ollama model directory: /synthetic/models" in result.output
    assert "checked at /synthetic" in result.output
    assert "MODEL_TIER=cloud" in (tmp_path / ".env").read_text(encoding="utf-8")
    assert "LLM_PROVIDER=anthropic" in (tmp_path / ".env").read_text(encoding="utf-8")


def test_triage_warns_before_confirmation_and_low_disk_is_warning_only(
    monkeypatch, tmp_path
) -> None:
    result = run_setup(monkeypatch, tmp_path, "2\ny\n1\n", facts(free_disk=1.5))

    assert result.exit_code == 0, result.output
    assert result.output.index("Warning: local-3b-triage") < result.output.index(
        "Continue with the triage-only tier?"
    )
    assert "needs approximately 2 GB" in result.output
    assert "Saved MODEL_TIER=local-3b-triage" in result.output


def test_existing_env_values_require_approval_and_are_preserved_on_rejection(
    monkeypatch, tmp_path
) -> None:
    env_file = tmp_path / ".env"
    original = "MODEL_TIER=local-3b-triage\nLLM_PROVIDER=openai\nKEEP=secret\n"
    env_file.write_text(original, encoding="utf-8")

    result = run_setup(monkeypatch, tmp_path, "1\n2\nn\n", facts())

    assert result.exit_code == 1
    assert ".env already sets MODEL_TIER=local-3b-triage" in result.output
    assert "Existing MODEL_TIER preserved" in result.output
    assert env_file.read_text(encoding="utf-8") == original


def test_existing_env_values_are_updated_only_after_approval(monkeypatch, tmp_path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("MODEL_TIER=local-3b-triage\nLLM_PROVIDER=openai\n", encoding="utf-8")

    result = run_setup(monkeypatch, tmp_path, "1\n5\ny\ny\n", facts())

    assert result.exit_code == 0, result.output
    saved = env_file.read_text(encoding="utf-8")
    assert "MODEL_TIER=cloud" in saved
    assert "LLM_PROVIDER=gemini" in saved
