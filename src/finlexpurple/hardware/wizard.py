"""Interactive hardware and model-tier setup wizard."""

from __future__ import annotations

from pathlib import Path

import typer
from dotenv import dotenv_values, set_key

from finlexpurple.config import LLMProvider
from finlexpurple.hardware.detect import HardwareFacts, detect_hardware
from finlexpurple.hardware.profiles import hardware_profile
from finlexpurple.hardware.tiers import (
    APPROXIMATE_MODEL_SIZES_GB,
    ModelTier,
    available_tiers,
    recommend_tier,
    recommendation_reason,
)

_PROVIDER_CHOICES = (
    ("ollama", "Ollama (local)"),
    ("anthropic", "Anthropic (cloud)"),
    ("openai", "OpenAI (cloud)"),
    ("openrouter", "OpenRouter (cloud)"),
    ("gemini", "Google Gemini (cloud)"),
)
_TRIAGE_WARNING = (
    "Warning: local-3b-triage is triage-only. It flags findings for stronger review, "
    "does not perform full exploitation reasoning, and has materially lower accuracy "
    "than cloud or GPU-backed options."
)


def _prompt_index(label: str, choices: tuple[str, ...], default: int = 1) -> int:
    for index, choice in enumerate(choices, start=1):
        typer.echo(f"  {index}. {choice}")
    while True:
        raw = typer.prompt(f"{label} [1-{len(choices)}]", default=str(default)).strip()
        try:
            selected = int(raw)
        except ValueError:
            typer.echo("Enter one of the listed numbers.")
            continue
        if 1 <= selected <= len(choices):
            return selected - 1
        typer.echo("Enter one of the listed numbers.")


def _choose_tier(hardware: HardwareFacts, recommendation: ModelTier) -> ModelTier:
    options = available_tiers(hardware)
    labels = tuple(
        f"{tier.value} (recommended)" if tier is recommendation else tier.value
        for tier in options
    )
    while True:
        selected = options[_prompt_index("Choose a model tier", labels)]
        if selected is ModelTier.LOCAL_3B_TRIAGE:
            typer.echo(_TRIAGE_WARNING)
            if not typer.confirm("Continue with the triage-only tier?", default=False):
                continue
        return selected


def _provider_incompatibility(tier: ModelTier, provider: LLMProvider) -> str | None:
    if tier is ModelTier.CLOUD and provider is LLMProvider.OLLAMA:
        return "The cloud tier requires a cloud provider; Ollama is incompatible."
    if tier is not ModelTier.CLOUD and provider is not LLMProvider.OLLAMA:
        if tier is ModelTier.LOCAL_8B_HYBRID:
            return (
                "The local-8b-hybrid tier currently requires Ollama; its cloud fallback "
                "can be configured separately as an optional provider."
            )
        return f"The {tier.value} tier requires Ollama; cloud providers are incompatible."
    return None


def _choose_provider(tier: ModelTier) -> LLMProvider:
    choices = _PROVIDER_CHOICES[1:] if tier is ModelTier.CLOUD else _PROVIDER_CHOICES
    labels = tuple(label for _, label in choices)
    while True:
        name = choices[_prompt_index("Choose a provider", labels)][0]
        provider = LLMProvider(name)
        error = _provider_incompatibility(tier, provider)
        if error is None:
            return provider
        typer.echo(error)


def _persist_selections(
    env_path: Path,
    tier: ModelTier,
    provider: LLMProvider,
    fallback_provider: LLMProvider | None = None,
) -> bool:
    """Persist the selections, asking before changing any nonempty .env values."""

    updates = {"MODEL_TIER": tier.value, "LLM_PROVIDER": provider.value}
    if fallback_provider is not None:
        updates["FALLBACK_LLM_PROVIDER"] = fallback_provider.value
    try:
        existing = dotenv_values(env_path) if env_path.exists() else {}
        for key, value in updates.items():
            old_value = existing.get(key)
            if old_value and old_value.strip() != value and not typer.confirm(
                f".env already sets {key}={old_value}. Replace it with {value}?",
                default=False,
            ):
                typer.echo(f"Existing {key} preserved; setup selections were not saved.")
                return False
        for key, value in updates.items():
            set_key(env_path, key, value, quote_mode="auto", encoding="utf-8")
    except OSError as exc:
        typer.echo(f"Could not save setup selections to {env_path}: {exc}", err=True)
        return False
    return True


def _show_hardware(hardware: HardwareFacts) -> None:
    for warning in hardware.warnings:
        typer.echo(f"Hardware detection warning: {warning}")
    typer.echo(f"Operating system: {hardware.operating_system}")
    typer.echo(f"Total system RAM: {hardware.total_ram_gb:.1f} GB")
    if hardware.gpu_kind == "none":
        typer.echo("GPU: no dedicated GPU detected")
    else:
        memory_label = "unified memory" if hardware.gpu_kind == "apple_silicon" else "VRAM"
        typer.echo(f"GPU: {hardware.gpu_name} ({hardware.gpu_memory_gb:.1f} GB {memory_label})")
    typer.echo(f"Ollama model directory: {hardware.model_directory}")
    typer.echo(
        f"Free disk space: {hardware.free_disk_gb:.1f} GB "
        f"(checked at {hardware.disk_checked_path})"
    )


def run_setup(
    env_path: Path | None = None,
    hardware: HardwareFacts | None = None,
    fake_hardware_profile: str | None = None,
) -> bool:
    """Run setup interactively and return whether its choices were persisted."""

    if hardware is not None and fake_hardware_profile is not None:
        raise ValueError("Pass either hardware facts or a fake profile, not both.")
    facts = hardware or (
        hardware_profile(fake_hardware_profile)
        if fake_hardware_profile is not None
        else detect_hardware()
    )
    _show_hardware(facts)
    recommendation = recommend_tier(facts)
    typer.echo(f"Recommended tier: {recommendation.value}. {recommendation_reason(facts, recommendation)}")
    tier = _choose_tier(facts, recommendation)
    provider = _choose_provider(tier)
    fallback_provider = None
    if tier is ModelTier.LOCAL_8B_HYBRID and typer.confirm(
        "Configure an optional cloud fallback provider? (configuration only; automatic routing is not active)",
        default=False,
    ):
        cloud_choices = _PROVIDER_CHOICES[1:]
        fallback_provider = LLMProvider(
            cloud_choices[
                _prompt_index("Choose a cloud fallback provider", tuple(label for _, label in cloud_choices))
            ][0]
        )

    needed = APPROXIMATE_MODEL_SIZES_GB.get(tier.value)
    if needed is not None and facts.free_disk_gb < needed:
        typer.echo(
            f"Warning: {tier.value} needs approximately {needed:g} GB for a model; "
            f"only {facts.free_disk_gb:.1f} GB is free at {facts.disk_checked_path}. "
            "You can continue, but there may not be enough space to download it."
        )

    target = env_path or (Path.cwd() / ".env")
    if not _persist_selections(target, tier, provider, fallback_provider):
        return False
    typer.echo(f"Saved MODEL_TIER={tier.value} and LLM_PROVIDER={provider.value} to {target}.")
    if provider is not LLMProvider.OLLAMA:
        key_name = f"{provider.value.upper()}_API_KEY"
        typer.echo(f"Before using this provider, add {key_name} to {target}.")
    if tier is ModelTier.LOCAL_8B_HYBRID:
        if fallback_provider is None:
            typer.echo("No cloud fallback provider was configured.")
        else:
            typer.echo(f"Saved FALLBACK_LLM_PROVIDER={fallback_provider.value} to {target}.")
            typer.echo(
                "Add its API key before use. This phase stores fallback configuration only; "
                "requests continue to use Ollama."
            )
    return True
