"""Boundary tests for automatic and manual tier choices."""

from __future__ import annotations

from pathlib import Path

import pytest

from finlexpurple.hardware.detect import HardwareFacts
from finlexpurple.hardware.tiers import ModelTier, available_tiers, recommend_tier


def facts(gpu_kind: str, memory: float | None, ram: float = 32) -> HardwareFacts:
    return HardwareFacts(
        total_ram_gb=ram,
        model_directory=Path("/models"),
        disk_checked_path=Path("/"),
        free_disk_gb=100,
        gpu_kind=gpu_kind,
        gpu_name="Synthetic GPU" if memory is not None else None,
        gpu_memory_gb=memory,
        operating_system="Synthetic",
    )


@pytest.mark.parametrize(
    ("hardware", "expected"),
    [
        (facts("nvidia", 24), ModelTier.LOCAL_30B),
        (facts("apple_silicon", 24), ModelTier.LOCAL_30B),
        (facts("nvidia", 23.9), ModelTier.LOCAL_8B_HYBRID),
        (facts("amd", 16), ModelTier.LOCAL_8B_HYBRID),
        (facts("nvidia", 8), ModelTier.LOCAL_8B_HYBRID),
        (facts("nvidia", 7.9, ram=64), ModelTier.CLOUD),
        (facts("apple_silicon", 23.9), ModelTier.LOCAL_8B_HYBRID),
        (facts("apple_silicon", 16), ModelTier.LOCAL_8B_HYBRID),
        (facts("apple_silicon", 15.9), ModelTier.CLOUD),
        (facts("none", None, ram=64), ModelTier.CLOUD),
        (facts("none", None, ram=4), ModelTier.CLOUD),
    ],
)
def test_recommendation_boundaries(hardware: HardwareFacts, expected: ModelTier) -> None:
    assert recommend_tier(hardware) is expected


@pytest.mark.parametrize(
    ("hardware", "triage_offered"),
    [
        (facts("none", None, ram=7.9), False),
        (facts("none", None, ram=8), True),
        (facts("nvidia", 7.9, ram=8), True),
    ],
)
def test_triage_is_only_a_manual_ram_gated_option(
    hardware: HardwareFacts, triage_offered: bool
) -> None:
    choices = available_tiers(hardware)

    assert (ModelTier.LOCAL_3B_TRIAGE in choices) is triage_offered
    assert recommend_tier(hardware) is not ModelTier.LOCAL_3B_TRIAGE
    if hardware.gpu_kind == "none" and hardware.total_ram_gb < 8:
        assert choices == (ModelTier.CLOUD,)
