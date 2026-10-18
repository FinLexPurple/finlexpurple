"""Synthetic platform tests for hardware discovery."""

from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

from finlexpurple.hardware import detect


def test_detects_nvidia_and_nearest_existing_model_parent(monkeypatch, tmp_path: Path) -> None:
    existing_parent = tmp_path / "ollama"
    existing_parent.mkdir()
    model_dir = existing_parent / "models"
    monkeypatch.setenv("OLLAMA_MODELS", str(model_dir))
    monkeypatch.setattr(detect.platform, "system", lambda: "Linux")
    monkeypatch.setattr(detect.platform, "platform", lambda: "Linux synthetic")
    monkeypatch.setattr(detect, "_total_memory_bytes", lambda _: 16 * detect._GIB)
    monkeypatch.setattr(detect, "_nvidia_gpu", lambda: ("Synthetic GPU", 12.0))
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


def test_detects_apple_silicon_unified_memory(monkeypatch, tmp_path: Path) -> None:
    model_dir = tmp_path / "models"
    model_dir.mkdir()
    monkeypatch.setenv("OLLAMA_MODELS", str(model_dir))
    monkeypatch.setattr(detect.platform, "system", lambda: "Darwin")
    monkeypatch.setattr(detect.platform, "machine", lambda: "arm64")
    monkeypatch.setattr(detect.platform, "platform", lambda: "macOS synthetic")
    monkeypatch.setattr(detect, "_total_memory_bytes", lambda _: 8 * detect._GIB)
    monkeypatch.setattr(detect, "_apple_silicon_unified_memory", lambda: 16 * detect._GIB)
    monkeypatch.setattr(detect, "_nvidia_gpu", lambda: None)
    monkeypatch.setattr(
        detect.shutil,
        "disk_usage",
        lambda path: SimpleNamespace(free=30 * detect._GIB),
    )

    facts = detect.detect_hardware()

    assert facts.total_ram_gb == 16
    assert facts.gpu_kind == "apple_silicon"
    assert facts.gpu_memory_gb == 16
    assert facts.disk_checked_path == model_dir


def test_no_gpu_is_reported_when_nvidia_is_unavailable(monkeypatch, tmp_path: Path) -> None:
    model_dir = tmp_path / "models"
    model_dir.mkdir()
    monkeypatch.setenv("OLLAMA_MODELS", str(model_dir))
    monkeypatch.setattr(detect.platform, "system", lambda: "Linux")
    monkeypatch.setattr(detect.platform, "platform", lambda: "Linux synthetic")
    monkeypatch.setattr(detect, "_total_memory_bytes", lambda _: 8 * detect._GIB)
    monkeypatch.setattr(detect, "_nvidia_gpu", lambda: None)
    monkeypatch.setattr(
        detect.shutil,
        "disk_usage",
        lambda path: SimpleNamespace(free=30 * detect._GIB),
    )

    facts = detect.detect_hardware()

    assert facts.gpu_kind == "none"
    assert facts.gpu_name is None
    assert facts.gpu_memory_gb is None
