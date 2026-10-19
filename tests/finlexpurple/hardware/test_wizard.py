"""Interactive setup wizard tests with synthetic hardware facts."""

from __future__ import annotations

import re
from pathlib import Path

import pytest
from dotenv import dotenv_values
from typer.testing import CliRunner

from finlexpurple.cli import app
from finlexpurple.config import LLMProvider
from finlexpurple.hardware import wizard
from finlexpurple.hardware.detect import HardwareFacts
from finlexpurple.hardware.tiers import ModelTier

runner = CliRunner()
_ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def strip_ansi(output: str) -> str:
    return _ANSI_ESCAPE.sub("", output)


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
        (
            "1\n2\n1\nn\n",
            "nvidia",
            24.0,
            "local-30b tier requires Ollama",
        ),
        (
            "1\n2\n1\nn\n",
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
    output = strip_ansi(result.output)

    assert result.exit_code == 0, output
    assert expected_message in output
    assert "Saved MODEL_TIER=" in output
    if "local-8b-hybrid" in expected_message:
        assert "No cloud fallback provider was configured" in output


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
    result = run_setup(monkeypatch, tmp_path, "1\n1\n", facts(ram=7.9))
    output = strip_ansi(result.output)

    assert result.exit_code == 0, output
    assert "local-3b-triage" not in output
    assert f"Ollama model directory: {Path('/synthetic/models')}" in output
    assert f"checked at {Path('/synthetic')}" in output
    assert "MODEL_TIER=cloud" in (tmp_path / ".env").read_text(encoding="utf-8")
    assert "LLM_PROVIDER=anthropic" in (tmp_path / ".env").read_text(encoding="utf-8")
    assert "Ollama (local)" not in output


def test_cloud_tier_defaults_to_first_cloud_provider(monkeypatch, tmp_path) -> None:
    result = run_setup(monkeypatch, tmp_path, "1\n\n", facts(ram=4))
    output = strip_ansi(result.output)

    assert result.exit_code == 0, output
    assert "1. Anthropic (cloud)" in output
    assert "LLM_PROVIDER=anthropic" in (tmp_path / ".env").read_text(encoding="utf-8")


def test_hybrid_can_save_optional_cloud_fallback_without_changing_active_provider(
    monkeypatch, tmp_path
) -> None:
    result = run_setup(
        monkeypatch,
        tmp_path,
        "1\n1\ny\n2\n",
        facts(ram=16, gpu_kind="nvidia", gpu_memory=12),
    )
    output = strip_ansi(result.output)
    saved = (tmp_path / ".env").read_text(encoding="utf-8")

    assert result.exit_code == 0, output
    assert "LLM_PROVIDER=ollama" in saved
    assert "FALLBACK_LLM_PROVIDER=openai" in saved
    assert "configuration only" in output
    assert "requests continue to use Ollama" in output


def test_triage_warns_before_confirmation_and_low_disk_is_warning_only(
    monkeypatch, tmp_path
) -> None:
    result = run_setup(monkeypatch, tmp_path, "2\ny\n1\n", facts(free_disk=1.5))
    output = strip_ansi(result.output)

    assert result.exit_code == 0, output
    assert output.index("Warning: local-3b-triage") < output.index(
        "Continue with the triage-only tier?"
    )
    assert "needs approximately 2 GB" in output
    assert "Saved MODEL_TIER=local-3b-triage" in output


def test_existing_env_values_require_approval_and_are_preserved_on_rejection(
    monkeypatch, tmp_path
) -> None:
    env_file = tmp_path / ".env"
    original = "MODEL_TIER=local-3b-triage\nLLM_PROVIDER=openai\nKEEP=secret\n"
    env_file.write_text(original, encoding="utf-8")

    result = run_setup(monkeypatch, tmp_path, "1\n2\nn\n", facts())
    output = strip_ansi(result.output)

    assert result.exit_code == 1
    assert ".env already sets MODEL_TIER=local-3b-triage" in output
    assert "Existing MODEL_TIER preserved" in output
    assert env_file.read_text(encoding="utf-8") == original


def test_existing_env_values_are_updated_only_after_approval(monkeypatch, tmp_path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("MODEL_TIER=local-3b-triage\nLLM_PROVIDER=openai\n", encoding="utf-8")

    result = run_setup(monkeypatch, tmp_path, "1\n4\ny\ny\n", facts())

    assert result.exit_code == 0, strip_ansi(result.output)
    saved = env_file.read_text(encoding="utf-8")
    assert "MODEL_TIER=cloud" in saved
    assert "LLM_PROVIDER=gemini" in saved


@pytest.mark.parametrize(
    ("profile", "expected_tier", "expected_provider"),
    [
        ("apple-8gb", "cloud", "anthropic"),
        ("apple-16gb", "local-8b-hybrid", "ollama"),
        ("apple-24gb", "local-30b", "ollama"),
        ("apple-32gb", "local-30b", "ollama"),
        ("nvidia-8gb", "local-8b-hybrid", "ollama"),
        ("nvidia-12gb", "local-8b-hybrid", "ollama"),
        ("nvidia-24gb", "local-30b", "ollama"),
        ("amd-16gb", "local-8b-hybrid", "ollama"),
        ("no-gpu", "cloud", "anthropic"),
        ("low-ram", "cloud", "anthropic"),
        ("low-disk", "cloud", "anthropic"),
        ("no-gpu-8gb-ram", "cloud", "anthropic"),
    ],
)
def test_synthetic_profiles_complete_setup_flow(
    monkeypatch, tmp_path: Path, profile: str, expected_tier: str, expected_provider: str
) -> None:
    monkeypatch.chdir(tmp_path)
    inputs = "1\n1\nn\n" if expected_tier == "local-8b-hybrid" else "1\n1\n"
    result = runner.invoke(app, ["setup", "--fake-hardware-profile", profile], input=inputs)
    output = strip_ansi(result.output)
    saved = dotenv_values(tmp_path / ".env") if (tmp_path / ".env").exists() else {}

    assert result.exit_code == 0, output
    assert f"Recommended tier: {expected_tier}." in output
    assert f"Saved MODEL_TIER={expected_tier} and LLM_PROVIDER={expected_provider}" in output
    assert saved["MODEL_TIER"] == expected_tier
    assert saved["LLM_PROVIDER"] == expected_provider
