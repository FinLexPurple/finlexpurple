"""Pure model-tier recommendation rules for detected hardware."""

from __future__ import annotations

from enum import Enum

from finlexpurple.hardware.detect import HardwareFacts

# Approximate quantized model downloads in GB. Adjust these as model defaults evolve.
APPROXIMATE_MODEL_SIZES_GB: dict[str, float] = {
    "local-30b": 20.0,
    "local-8b-hybrid": 5.0,
    "local-3b-triage": 2.0,
}


class ModelTier(str, Enum):
    """Supported model tiers stored in the user's local configuration."""

    CLOUD = "cloud"
    LOCAL_30B = "local-30b"
    LOCAL_8B_HYBRID = "local-8b-hybrid"
    LOCAL_3B_TRIAGE = "local-3b-triage"


def recommend_tier(hardware: HardwareFacts) -> ModelTier:
    """Return the automatic recommendation; the triage tier is never automatic."""

    memory = hardware.gpu_memory_gb
    if hardware.gpu_kind != "none" and memory is not None and memory >= 24:
        return ModelTier.LOCAL_30B
    if hardware.gpu_kind == "nvidia" and memory is not None and 8 <= memory < 24:
        return ModelTier.LOCAL_8B_HYBRID
    if hardware.gpu_kind == "apple_silicon" and memory is not None and 16 <= memory < 24:
        return ModelTier.LOCAL_8B_HYBRID
    return ModelTier.CLOUD


def available_tiers(hardware: HardwareFacts) -> tuple[ModelTier, ...]:
    """Return the recommendation and manual overrides appropriate to this host."""

    recommendation = recommend_tier(hardware)
    options: list[ModelTier] = [ModelTier.CLOUD]
    memory = hardware.gpu_memory_gb
    if hardware.gpu_kind == "nvidia" and memory is not None:
        if memory >= 8:
            options.append(ModelTier.LOCAL_8B_HYBRID)
        if memory >= 24:
            options.append(ModelTier.LOCAL_30B)
    elif hardware.gpu_kind == "apple_silicon" and memory is not None:
        if memory >= 16:
            options.append(ModelTier.LOCAL_8B_HYBRID)
        if memory >= 24:
            options.append(ModelTier.LOCAL_30B)
    if hardware.total_ram_gb >= 8:
        options.append(ModelTier.LOCAL_3B_TRIAGE)
    if recommendation != ModelTier.CLOUD and recommendation not in options:
        options.append(recommendation)
    # Put the automatic recommendation first so accepting the default is obvious.
    options.remove(recommendation)
    options.insert(0, recommendation)
    return tuple(options)


def recommendation_reason(hardware: HardwareFacts, tier: ModelTier) -> str:
    """Provide the one-sentence explanation shown by the setup wizard."""

    if tier is ModelTier.LOCAL_30B:
        return "Detected at least 24 GB of GPU or Apple unified memory for a 30B model."
    if tier is ModelTier.LOCAL_8B_HYBRID:
        return "Detected enough GPU or Apple unified memory for an 8B model, but less than 24 GB."
    if hardware.gpu_kind == "none":
        return "No capable local GPU was detected, so cloud is the safest default recommendation."
    return "Detected GPU memory is below 8 GB, so cloud is the recommended tier."
