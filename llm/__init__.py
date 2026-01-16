"""
LLM module for CVE tagging.

This module provides local LLM-based tagging for CVEs to enable
kill chain reconstruction and attack pattern analysis.

Main components:
- CVETagger: Main class for tagging CVEs
- OllamaBackend: Ollama API backend
- taxonomy: Tag definitions and validation

Example usage:
    from llm import CVETagger

    tagger = CVETagger()
    if tagger.is_available():
        result = tagger.tag_cve(enriched_cve_data)
        # result contains: kill_chain_phases, prerequisites, capabilities
"""

from .base import BaseLLMBackend, LLMConfig, LLMResponse
from .config import LLMTaggerConfig, DEFAULT_CONFIG
from .ollama_backend import OllamaBackend
from .tagger import CVETagger
from .taxonomy import (
    TAXONOMY_VERSION,
    KILL_CHAIN_PHASES,
    PREREQUISITES,
    CAPABILITIES,
    validate_tags_by_category,
)
from .validator import TagCoherenceValidator, validate_tag_coherence

__all__ = [
    # Main classes
    "CVETagger",
    "OllamaBackend",
    # Base classes
    "BaseLLMBackend",
    "LLMConfig",
    "LLMResponse",
    # Configuration
    "LLMTaggerConfig",
    "DEFAULT_CONFIG",
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
