"""Explicit synthetic host profiles for safe manual what-if checks."""

from __future__ import annotations

from pathlib import Path

from finlexpurple.hardware.detect import HardwareFacts

_PROFILES: dict[str, tuple[float, str, float | None, float]] = {
    "apple-8gb": (8, "apple_silicon", 8, 40),
    "apple-16gb": (16, "apple_silicon", 16, 40),
    "apple-24gb": (24, "apple_silicon", 24, 40),
    "apple-32gb": (32, "apple_silicon", 32, 40),
    "nvidia-8gb": (16, "nvidia", 8, 40),
    "nvidia-12gb": (32, "nvidia", 12, 40),
    "nvidia-24gb": (64, "nvidia", 24, 40),
    "amd-16gb": (32, "amd", 16, 40),
    "no-gpu": (16, "none", None, 40),
    "low-ram": (4, "none", None, 40),
    "low-disk": (16, "none", None, 1),
    "no-gpu-8gb-ram": (8, "none", None, 40),
}


def profile_names() -> tuple[str, ...]:
    """Return supported explicit synthetic hardware profile names."""

    return tuple(_PROFILES)


def hardware_profile(name: str) -> HardwareFacts:
    """Build synthetic facts for a named what-if profile."""

    try:
        ram, gpu_kind, gpu_memory, free_disk = _PROFILES[name]
    except KeyError:
        choices = ", ".join(profile_names())
        raise ValueError(f"Unknown hardware profile {name!r}. Choose one of: {choices}") from None
    return HardwareFacts(
        total_ram_gb=ram,
        model_directory=Path("<synthetic-models>"),
        disk_checked_path=Path("<synthetic-disk-path>"),
        free_disk_gb=free_disk,
        gpu_kind=gpu_kind,
        gpu_name=f"Synthetic {gpu_kind} GPU" if gpu_memory is not None else None,
        gpu_memory_gb=gpu_memory,
        operating_system="Synthetic profile",
    )
