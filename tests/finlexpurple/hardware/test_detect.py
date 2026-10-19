"""Synthetic platform tests for hardware discovery."""

from __future__ import annotations

import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from finlexpurple.cli import app
from finlexpurple.hardware import detect, wizard


def test_detects_nvidia_and_nearest_existing_model_parent(monkeypatch, tmp_path: Path) -> None:
    existing_parent = tmp_path / "ollama"
    existing_parent.mkdir()
    model_dir = existing_parent / "models"
    monkeypatch.setenv("OLLAMA_MODELS", str(model_dir))
    monkeypatch.setattr(detect.platform, "system", lambda: "Linux")
    monkeypatch.setattr(detect.platform, "platform", lambda: "Linux synthetic")
    monkeypatch.setattr(detect, "_total_memory_bytes", lambda _: 16 * detect._GIB)
    monkeypatch.setattr(
        detect, "_probe_nvidia_gpu", lambda: (("Synthetic GPU", 12.0), None)
    )
    monkeypatch.setattr(
        detect.shutil,
        "disk_usage",
        lambda path: SimpleNamespace(free=4 * detect._GIB),
    )

    facts = detect.detect_hardware()

    assert facts.total_ram_gb == 16
    assert facts.gpu_kind == "nvidia"
    assert facts.gpu_name == "Synthetic GPU"
    assert facts.gpu_memory_gb == 12
    assert facts.model_directory == model_dir
    assert facts.disk_checked_path == existing_parent
    assert facts.free_disk_gb == 4


def test_defaults_model_directory_by_platform(monkeypatch, tmp_path: Path) -> None:
    monkeypatch.delenv("OLLAMA_MODELS", raising=False)
    monkeypatch.setattr(detect.platform, "system", lambda: "Linux")
    monkeypatch.setattr(detect.Path, "home", lambda: tmp_path)

    assert detect._model_directory() == tmp_path / ".ollama" / "models"


@pytest.mark.parametrize("memory_gb", [16, 24])
def test_detects_apple_silicon_unified_memory(
    monkeypatch, tmp_path: Path, memory_gb: int
) -> None:
    model_dir = tmp_path / "models"
    model_dir.mkdir()
    monkeypatch.setenv("OLLAMA_MODELS", str(model_dir))
    monkeypatch.setattr(detect.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(detect.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(detect.platform, "platform", lambda: "macOS synthetic")
    monkeypatch.setattr(detect, "_total_memory_bytes", lambda _: 8 * detect._GIB)
    monkeypatch.setattr(
        detect,
        "_apple_silicon_unified_memory",
        lambda: memory_gb * detect._GIB,
    )
    monkeypatch.setattr(detect, "_probe_nvidia_gpu", lambda: (None, None))
    monkeypatch.setattr(
        detect.shutil,
        "disk_usage",
        lambda path: SimpleNamespace(free=30 * detect._GIB),
    )

    facts = detect.detect_hardware()

    assert facts.total_ram_gb == memory_gb
    assert facts.gpu_kind == "apple_silicon"
    assert facts.gpu_memory_gb == memory_gb
    assert facts.disk_checked_path == model_dir


@pytest.mark.parametrize(
    ("build", "expected"),
    [(21999, "Windows 10"), (22000, "Windows 11"), (26100, "Windows 11")],
)
def test_windows_version_label_uses_build_number(
    monkeypatch, build: int, expected: str
) -> None:
    monkeypatch.setattr(detect.platform, "system", lambda: "Windows")
    monkeypatch.setattr(
        detect.sys,
        "getwindowsversion",
        lambda: SimpleNamespace(major=10, build=build),
        raising=False,
    )

    assert detect._operating_system_label() == f"{expected} (build {build})"


def test_no_gpu_is_reported_when_nvidia_is_unavailable(monkeypatch, tmp_path: Path) -> None:
    model_dir = tmp_path / "models"
    model_dir.mkdir()
    monkeypatch.setenv("OLLAMA_MODELS", str(model_dir))
    monkeypatch.setattr(detect.platform, "system", lambda: "Linux")
    monkeypatch.setattr(detect.platform, "platform", lambda: "Linux synthetic")
    monkeypatch.setattr(detect, "_total_memory_bytes", lambda _: 8 * detect._GIB)
    monkeypatch.setattr(detect, "_probe_nvidia_gpu", lambda: (None, None))
    monkeypatch.setattr(
        detect.shutil,
        "disk_usage",
        lambda path: SimpleNamespace(free=30 * detect._GIB),
    )

    facts = detect.detect_hardware()

    assert facts.gpu_kind == "none"
    assert facts.gpu_name is None
    assert facts.gpu_memory_gb is None


@pytest.mark.parametrize(
    ("failure", "expected_message"),
    [
        ("missing", "nvidia-smi is unavailable"),
        ("nonzero", "nvidia-smi returned an error"),
        ("timeout", "nvidia-smi timed out"),
        ("empty", "no usable GPU facts"),
        ("garbage", "no usable GPU facts"),
    ],
)
def test_gpu_probe_failures_fall_back_to_cloud_without_crashing(
    monkeypatch, tmp_path: Path, failure: str, expected_message: str
) -> None:
    model_dir = tmp_path / "models"
    model_dir.mkdir()
    monkeypatch.setenv("OLLAMA_MODELS", str(model_dir))
    monkeypatch.setattr(detect.platform, "system", lambda: "Linux")
    monkeypatch.setattr(detect.platform, "platform", lambda: "Linux synthetic")
    if failure == "missing":
        def run(*args, **kwargs):
            raise FileNotFoundError("nvidia-smi")
    elif failure == "timeout":
        def run(*args, **kwargs):
            raise subprocess.TimeoutExpired(args[0], timeout=3)
    elif failure == "nonzero":
        def run(*args, **kwargs):
            return SimpleNamespace(returncode=1, stdout="", stderr="failed")
    else:
        output = "" if failure == "empty" else "not valid GPU output"
        def run(*args, **kwargs):
            return SimpleNamespace(returncode=0, stdout=output, stderr="")
    monkeypatch.setattr(detect.subprocess, "run", run)
    monkeypatch.setattr(
        detect.shutil,
        "disk_usage",
        lambda path: SimpleNamespace(free=30 * detect._GIB),
    )

    facts = detect.detect_hardware()

    assert facts.gpu_kind == "none"
    assert any(expected_message in warning for warning in facts.warnings)
    monkeypatch.setattr(wizard, "detect_hardware", lambda: facts)
    monkeypatch.chdir(tmp_path)
    result = CliRunner().invoke(app, ["setup"], input="1\n1\n")

    assert result.exit_code == 0, result.output
    assert "Recommended tier: cloud." in result.output
    assert "Hardware detection warning:" in result.output
    assert "Saved MODEL_TIER=cloud" in result.output
