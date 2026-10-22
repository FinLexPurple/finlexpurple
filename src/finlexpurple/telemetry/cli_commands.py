"""Backing logic for `telemetry show | on | off` (decisions.md §8).

``show`` lets the user inspect exactly what would be sent (the real install
payload plus example scan/feedback payloads, all built via the collector, so the
keys are always a subset of the allow-list), together with the plain-language
purpose statement §8 requires. ``on``/``off`` persist ``TELEMETRY_ENABLED`` to
``.env``; turning it on also materializes the local install id so it is ready.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from dotenv import set_key

from finlexpurple.config import Config
from finlexpurple.telemetry import allowlist, collector
from finlexpurple.telemetry.install_counter import get_or_create_install_id

# Stated plainly wherever telemetry is mentioned to the user (§8).
PURPOSE = (
    "Telemetry is opt-in and off by default. Its only purpose is to improve "
    "detection accuracy and false-positive rates over time. It is never used for "
    "ad targeting, resale, or any other purpose. Only the allow-listed fields "
    "below are ever sent — never your target, scan data, source code, or API keys."
)


def preview_payloads(install_id: str) -> dict[str, dict[str, Any]]:
    """The payloads that could be sent, built via the collector (allow-listed)."""

    return {
        "install": collector.build_install_payload(install_id),
        "scan_summary (example)": collector.build_scan_summary_payload(
            total_findings=0,
            verified=0,
            verified_percent=0.0,
            severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
            vulnerability_classes=[],
        ),
        "feedback (example)": collector.build_feedback_payload(
            run_rating="good", finding_mark="false-positive", vulnerability_class="sqli"
        ),
    }


def describe_telemetry(config: Config, *, install_id: str) -> str:
    """Render the full `telemetry show` text: state, purpose, allow-list, preview."""

    state = "ON" if config.telemetry_enabled else "OFF (default)"
    endpoint = config.telemetry_endpoint or "(not configured — nothing can be sent)"
    lines = [
        f"Telemetry: {state}",
        f"Endpoint:  {endpoint}",
        "",
        PURPOSE,
        "",
        "Allow-listed fields (the only fields that may ever be sent):",
        "  " + ", ".join(sorted(allowlist.ALLOWED_FIELDS)),
        "",
        "Exactly what would be sent:",
        json.dumps(preview_payloads(install_id), indent=2, sort_keys=True),
    ]
    return "\n".join(lines)


def enable_telemetry(env_path: Path) -> str:
    """Persist TELEMETRY_ENABLED=true and ensure the install id exists."""

    set_key(str(env_path), "TELEMETRY_ENABLED", "true", quote_mode="never", encoding="utf-8")
    get_or_create_install_id()  # materialize the local install id so it is ready
    return (
        f"Telemetry enabled (saved to {env_path}). Install id ready. "
        "Run 'finlexpurple telemetry show' to see exactly what would be sent, "
        "or 'finlexpurple telemetry off' to turn it back off."
    )


def disable_telemetry(env_path: Path) -> str:
    """Persist TELEMETRY_ENABLED=false."""

    set_key(str(env_path), "TELEMETRY_ENABLED", "false", quote_mode="never", encoding="utf-8")
    return f"Telemetry disabled (saved to {env_path})."
