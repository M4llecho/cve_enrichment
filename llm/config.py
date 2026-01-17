"""
LLM Configuration for CVE Tagger.
"""

import os
from dataclasses import dataclass, field

# Load .env file before reading environment variables
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from .base import LLMConfig


# Environment variable names
ENV_LLM_BACKEND = "CVE_LLM_BACKEND"
ENV_LLM_MODEL = "CVE_LLM_MODEL"
ENV_LLM_URL = "CVE_LLM_URL"
ENV_LLM_TEMPERATURE = "CVE_LLM_TEMPERATURE"
ENV_LLM_TIMEOUT = "CVE_LLM_TIMEOUT"

# API backend environment variables
ENV_LLM_API_PROVIDER = "CVE_LLM_API_PROVIDER"
ENV_LLM_API_KEY = "CVE_LLM_API_KEY"


@dataclass
class LLMTaggerConfig:
    """Configuration for the LLM tagger system."""

    # Backend selection: "ollama", "llamacpp", or "api"
    backend: str = field(
        default_factory=lambda: os.getenv(ENV_LLM_BACKEND, "ollama")
    )

    # API provider (only used when backend="api"): gemini, deepseek, openai, anthropic, groq
    api_provider: str = field(
        default_factory=lambda: os.getenv(ENV_LLM_API_PROVIDER, "gemini")
    )

    # Model configuration
    model: str = field(
        default_factory=lambda: os.getenv(ENV_LLM_MODEL, "deepseek-r1:8b")
    )
    temperature: float = field(
        default_factory=lambda: float(os.getenv(ENV_LLM_TEMPERATURE, "0.1"))
    )

    # Connection
    # Default to Windows host IP for WSL, override with ENV_LLM_URL if needed
    base_url: str = field(
        default_factory=lambda: os.getenv(ENV_LLM_URL, "http://172.29.96.1:11434")
    )

    # Timeout per request
    timeout: int = field(
        default_factory=lambda: int(os.getenv(ENV_LLM_TIMEOUT, "120"))
    )

    # Processing settings
    batch_size: int = 100  # CVEs per batch for DB updates
    max_retries: int = 3
    retry_delay: float = 5.0

    def to_llm_config(self) -> LLMConfig:
        """Convert to LLMConfig for backend initialization."""
        return LLMConfig(
            model=self.model,
            temperature=self.temperature,
            base_url=self.base_url,
            timeout=self.timeout,
            max_retries=self.max_retries,
            retry_delay=self.retry_delay,
        )


# Default configuration instance
DEFAULT_CONFIG = LLMTaggerConfig()


# Recommended models for CVE tagging (by backend)
RECOMMENDED_MODELS = {
    "ollama": [
        "deepseek-r1:8b",   # Great reasoning for complex CVEs (default)
        "gemma3:12b",       # Best for structured JSON output
        "qwen2.5:14b",      # Excellent JSON, needs more VRAM
        "qwen2.5:7b",       # Fast and reliable
        "gemma3:4b",        # Ultra-fast, lower quality
    ],
    "llamacpp": [
        "gemma-3-12b-instruct.gguf",
        "qwen2.5-7b-instruct.gguf",
    ],
    "api": {
        "gemini": "gemini-2.5-flash",       # Best value: $0.15/$0.60 per MTok
        "deepseek": "deepseek-chat",        # Cheapest: $0.28/$0.42 per MTok
        "openai": "gpt-4o",                 # Premium: $2.50/$10 per MTok
        "anthropic": "claude-3-5-haiku-latest",  # Quality: $0.80/$4 per MTok
        "groq": "llama-3.3-70b-versatile",  # Fastest: $0.59/$0.79 per MTok
    },
}


def get_recommended_model(backend: str = "ollama", api_provider: str = "gemini") -> str:
    """Get recommended model for the specified backend."""
    if backend == "api":
        api_models = RECOMMENDED_MODELS.get("api", {})
        return api_models.get(api_provider, "gemini-2.5-flash")
    models = RECOMMENDED_MODELS.get(backend, [])
    return models[0] if models else "gemma3:12b"
