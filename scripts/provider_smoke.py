"""One-request, manually dispatched live provider smoke check for CI."""

from __future__ import annotations

import os
import sys

from finlexpurple.config import Config, LLMProvider
from finlexpurple.providers.base import Message
from finlexpurple.providers.factory import create_provider

_KEY_NAMES = {
    LLMProvider.ANTHROPIC: "ANTHROPIC_API_KEY",
    LLMProvider.OPENAI: "OPENAI_API_KEY",
    LLMProvider.OPENROUTER: "OPENROUTER_API_KEY",
    LLMProvider.GEMINI: "GEMINI_API_KEY",
}


def main() -> int:
    """Run only the requested cloud provider; never print the secret or response."""

    provider_text = os.environ.get("INPUT_PROVIDER", "")
    try:
        provider_name = LLMProvider(provider_text)
    except ValueError:
        print("Choose a supported cloud provider in workflow_dispatch.")
        return 2
    key_name = _KEY_NAMES.get(provider_name)
    if key_name is None:
        print("Live smoke supports cloud providers only.")
        return 2
    if not os.environ.get(key_name, "").strip():
        print(f"Skipped: repository secret {key_name} is not configured.")
        return 0

    os.environ["LLM_PROVIDER"] = provider_name.value
    try:
        provider = create_provider(Config.load())
        response = provider.complete([Message(role="user", content="Reply with OK.")])
        if not response.content.strip():
            print(f"Live provider smoke returned empty output for {provider_name.value}.")
            return 1
    except Exception as exc:  # noqa: BLE001 - suppress SDK details that may contain secrets.
        # SDK messages can contain request details. Keep output to a type name.
        print(f"Live provider smoke failed for {provider_name.value} ({type(exc).__name__}).")
        return 1
    print(f"Live provider smoke passed for {provider_name.value}; response was not displayed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
