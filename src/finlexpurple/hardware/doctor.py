"""Privacy-conscious display of detected or explicitly simulated facts."""

from __future__ import annotations

from finlexpurple.hardware.detect import HardwareFacts


def format_facts(facts: HardwareFacts) -> str:
    """Format hardware facts without printing user-specific filesystem paths."""

    gpu = "none detected"
    if facts.gpu_kind != "none":
        gpu = f"{facts.gpu_kind}: {facts.gpu_name or 'unknown'}"
        if facts.gpu_memory_gb is not None:
            gpu += f" ({facts.gpu_memory_gb:.1f} GB)"
    checked_location = (
        "configured model directory"
        if facts.disk_checked_path == facts.model_directory
        else "nearest existing parent of model directory"
    )
    lines = [
        f"Operating system: {facts.operating_system}",
        f"Total system RAM: {facts.total_ram_gb:.1f} GB",
        f"GPU: {gpu}",
        f"Model directory exists: {facts.model_directory.exists()}",
        f"Disk space checked at: {checked_location}",
        f"Free disk space: {facts.free_disk_gb:.1f} GB",
    ]
    lines.extend(f"Hardware detection warning: {warning}" for warning in facts.warnings)
    return "\n".join(lines)
