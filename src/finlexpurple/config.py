"""Environment-backed application configuration."""

from __future__ import annotations

import os
from enum import Enum
from pathlib import Path
from typing import Any

from dotenv import load_dotenv
from pydantic import Field, ValidationError, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

from finlexpurple.hardware.tiers import ModelTier


class LLMProvider(str, Enum):
    """Supported model providers."""

    OLLAMA = "ollama"
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    OPENROUTER = "openrouter"
    GEMINI = "gemini"


class ConfigurationError(ValueError):
    """A user-correctable configuration error with no validation traceback."""


class Config(BaseSettings):
    """Typed settings matching the variables in ``.env.example``."""

    model_config = SettingsConfigDict(
        env_prefix="",
        env_file=".env",
        env_file_encoding="utf-8",
        env_ignore_empty=True,
        case_sensitive=False,
        extra="ignore",
    )

    llm_provider: LLMProvider = Field(default=LLMProvider.OLLAMA, validation_alias="LLM_PROVIDER")
    ollama_model: str | None = Field(default=None, validation_alias="OLLAMA_MODEL")
    ollama_host: str = Field(default="http://localhost:11434", validation_alias="OLLAMA_HOST")
    anthropic_model: str = Field(default="claude-sonnet-5-5", validation_alias="ANTHROPIC_MODEL")
    openai_model: str = Field(default="gpt-6.1-sol", validation_alias="OPENAI_MODEL")
    openrouter_model: str = Field(
        default="openai/gpt-6-luna", validation_alias="OPENROUTER_MODEL"
    )
    gemini_model: str = Field(default="gemini-3.8-flash", validation_alias="GEMINI_MODEL")
    fallback_llm_provider: LLMProvider | None = Field(
        default=None, validation_alias="FALLBACK_LLM_PROVIDER"
    )
    anthropic_api_key: str | None = Field(default=None, validation_alias="ANTHROPIC_API_KEY")
    openai_api_key: str | None = Field(default=None, validation_alias="OPENAI_API_KEY")
    openrouter_api_key: str | None = Field(default=None, validation_alias="OPENROUTER_API_KEY")
    gemini_api_key: str | None = Field(default=None, validation_alias="GEMINI_API_KEY")
    require_human_approval: bool = Field(default=True, validation_alias="REQUIRE_HUMAN_APPROVAL")
    telemetry_enabled: bool = Field(default=False, validation_alias="TELEMETRY_ENABLED")
    model_tier: ModelTier | None = Field(default=None, validation_alias="MODEL_TIER")

    @field_validator("llm_provider", mode="before")
    @classmethod
    def validate_provider(cls, value: Any) -> Any:
        if isinstance(value, str):
            normalized = value.strip().lower()
            choices = ", ".join(provider.value for provider in LLMProvider)
            if normalized not in {provider.value for provider in LLMProvider}:
                raise ValueError(
                    f"invalid LLM_PROVIDER {value!r}; allowed providers: {choices}"
                )
            return normalized
        return value

    @field_validator("fallback_llm_provider", mode="before")
    @classmethod
    def validate_fallback_provider(cls, value: Any) -> Any:
        if value is None:
            return None
        if isinstance(value, str):
            normalized = value.strip().lower()
            cloud_providers = {provider.value for provider in LLMProvider if provider is not LLMProvider.OLLAMA}
            if normalized not in cloud_providers:
                choices = ", ".join(sorted(cloud_providers))
                raise ValueError(
                    f"invalid FALLBACK_LLM_PROVIDER {value!r}; allowed cloud providers: {choices}"
                )
            return normalized
        return value

    @field_validator("model_tier", mode="before")
    @classmethod
    def validate_model_tier(cls, value: Any) -> Any:
        if isinstance(value, str):
            normalized = value.strip().lower()
            choices = ", ".join(tier.value for tier in ModelTier)
            if normalized not in {tier.value for tier in ModelTier}:
                raise ValueError(f"invalid MODEL_TIER {value!r}; allowed tiers: {choices}")
            return normalized
        return value

    @field_validator("require_human_approval", "telemetry_enabled", mode="before")
    @classmethod
    def validate_boolean(cls, value: Any) -> Any:
        if isinstance(value, bool) or value is None:
            return value
        if isinstance(value, int) and value in (0, 1):
            return bool(value)
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"true", "1"}:
                return True
            if normalized in {"false", "0"}:
                return False
            raise ValueError(f"invalid boolean value {value!r}")
        return value

    @model_validator(mode="after")
    def require_cloud_key(self) -> Config:
        key_by_provider = {
            LLMProvider.ANTHROPIC: ("ANTHROPIC_API_KEY", self.anthropic_api_key),
            LLMProvider.OPENAI: ("OPENAI_API_KEY", self.openai_api_key),
            LLMProvider.OPENROUTER: ("OPENROUTER_API_KEY", self.openrouter_api_key),
            LLMProvider.GEMINI: ("GEMINI_API_KEY", self.gemini_api_key),
        }
        required_key = key_by_provider.get(self.llm_provider)
        if required_key and not (required_key[1] and required_key[1].strip()):
            raise ValueError(f"{required_key[0]} is required when LLM_PROVIDER={self.llm_provider.value}")
        if self.fallback_llm_provider is not None:
            if self.model_tier is not ModelTier.LOCAL_8B_HYBRID:
                raise ValueError(
                    "FALLBACK_LLM_PROVIDER is only supported when MODEL_TIER=local-8b-hybrid"
                )
            fallback_key = key_by_provider[self.fallback_llm_provider]
            if fallback_key and not (fallback_key[1] and fallback_key[1].strip()):
                raise ValueError(
                    f"{fallback_key[0]} is required when FALLBACK_LLM_PROVIDER="
                    f"{self.fallback_llm_provider.value}"
                )
        return self

    @classmethod
    def load(cls, env_path: Path | None = None) -> Config:
        """Load the current directory's .env and return validated settings."""

        dotenv_path = env_path or Path.cwd() / ".env"
        # Empty shell variables count as unset, allowing the .env value to apply.
        config_names = {
            "LLM_PROVIDER",
            "OLLAMA_MODEL",
            "OLLAMA_HOST",
            "ANTHROPIC_MODEL",
            "OPENAI_MODEL",
            "OPENROUTER_MODEL",
            "GEMINI_MODEL",
            "FALLBACK_LLM_PROVIDER",
            "ANTHROPIC_API_KEY",
            "OPENAI_API_KEY",
            "OPENROUTER_API_KEY",
            "GEMINI_API_KEY",
            "REQUIRE_HUMAN_APPROVAL",
            "TELEMETRY_ENABLED",
            "MODEL_TIER",
        }
        for name in config_names:
            if name in os.environ and not os.environ[name]:
                os.environ.pop(name)
        load_dotenv(dotenv_path=dotenv_path, override=False)
        try:
            return cls()
        except ValidationError as exc:
            messages = []
            aliases = {
                "require_human_approval": "REQUIRE_HUMAN_APPROVAL",
                "REQUIRE_HUMAN_APPROVAL": "REQUIRE_HUMAN_APPROVAL",
                "telemetry_enabled": "TELEMETRY_ENABLED",
                "TELEMETRY_ENABLED": "TELEMETRY_ENABLED",
            }
            for error in exc.errors():
                message = error["msg"].removeprefix("Value error, ")
                field = error["loc"][0] if error["loc"] else None
                if field in aliases:
                    message = f"{aliases[field]}: {message}"
                messages.append(message)
            raise ConfigurationError("Configuration error: " + "; ".join(messages)) from None

