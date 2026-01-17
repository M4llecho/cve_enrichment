"""
LLM module for CVE tagging.

This module provides LLM-based tagging for CVEs to enable
kill chain reconstruction and attack pattern analysis.

Main components:
- CVETagger: Main class for tagging CVEs
- OllamaBackend: Ollama API backend (local)
- APIBackend: Cloud API backend (Gemini, DeepSeek, OpenAI, Anthropic, Groq)
- create_backend: Factory function to create the right backend
- taxonomy: Tag definitions and validation

Example usage:
    from llm import CVETagger, create_backend

    # Use default backend (from CVE_LLM_BACKEND env var)
    tagger = CVETagger()

    # Or specify API backend
    backend = create_backend(backend="api", api_provider="gemini")
    tagger = CVETagger(backend=backend)

    if tagger.is_available():
        result = tagger.tag_cve(enriched_cve_data)
        # result contains: kill_chain_phases, prerequisites, capabilities
"""

import os
from typing import Optional

from .base import BaseLLMBackend, LLMConfig, LLMResponse
from .config import LLMTaggerConfig, DEFAULT_CONFIG, get_recommended_model
from .ollama_backend import OllamaBackend
from .api_backend import APIBackend
from .tagger import CVETagger
from .taxonomy import (
    TAXONOMY_VERSION,
    KILL_CHAIN_PHASES,
    PREREQUISITES,
    CAPABILITIES,
    validate_tags_by_category,
)
from .validator import TagCoherenceValidator, validate_tag_coherence


def create_backend(
    backend: Optional[str] = None,
    api_provider: Optional[str] = None,
    model: Optional[str] = None,
    config: Optional[LLMTaggerConfig] = None,
) -> BaseLLMBackend:
    """
    Factory function to create the appropriate LLM backend.

    Args:
        backend: Backend type ("ollama", "api"). Default from CVE_LLM_BACKEND env.
        api_provider: API provider for "api" backend ("gemini", "deepseek", etc.).
                      Default from CVE_LLM_API_PROVIDER env.
        model: Model name. Default from CVE_LLM_MODEL env or provider default.
        config: Optional LLMTaggerConfig. Creates default if not provided.

    Returns:
        Configured LLM backend instance.

    Environment variables:
        CVE_LLM_BACKEND: "ollama" or "api" (default: "ollama")
        CVE_LLM_API_PROVIDER: "gemini", "deepseek", "openai", "anthropic", "groq"
        CVE_LLM_MODEL: Model name (uses provider default if not set)
        GEMINI_API_KEY, DEEPSEEK_API_KEY, etc.: API keys for cloud providers

    Example:
        # Use environment variables
        backend = create_backend()

        # Explicit API backend with Gemini
        backend = create_backend(backend="api", api_provider="gemini")

        # Use with tagger
        tagger = CVETagger(backend=backend)
    """
    cfg = config or DEFAULT_CONFIG

    # Override with parameters if provided
    backend_type = backend or cfg.backend
    provider = api_provider or cfg.api_provider

    if backend_type == "api":
        # Get model - use provided, env var, or provider default
        api_model = model or os.getenv("CVE_LLM_MODEL") or get_recommended_model("api", provider)
        return APIBackend(
            provider=provider,
            model=api_model,
            config=cfg.to_llm_config(),
        )
    else:
        # Ollama backend (default)
        return OllamaBackend(cfg.to_llm_config())


__all__ = [
    # Main classes
    "CVETagger",
    "OllamaBackend",
    "APIBackend",
    # Factory
    "create_backend",
    # Base classes
    "BaseLLMBackend",
    "LLMConfig",
    "LLMResponse",
    # Configuration
    "LLMTaggerConfig",
    "DEFAULT_CONFIG",
    "get_recommended_model",
    # Taxonomy
    "TAXONOMY_VERSION",
    "KILL_CHAIN_PHASES",
    "PREREQUISITES",
    "CAPABILITIES",
    "validate_tags_by_category",
    # Validator
    "TagCoherenceValidator",
    "validate_tag_coherence",
]
