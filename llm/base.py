"""
Abstract base class for LLM backends.

Supports multiple backends: Ollama (default), llama.cpp (future).
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, Optional
import logging

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    """Response from LLM backend."""
    text: str
    model: str
    tokens_used: int
    generation_time: float
    raw_response: Optional[Dict[str, Any]] = None


@dataclass
class LLMConfig:
    """Configuration for LLM backend."""
    model: str = "llama3.2:8b"
    temperature: float = 0.1  # Low for deterministic output
    max_tokens: int = 16384  # High for reasoning models (DeepSeek-R1 needs room for thinking)
    top_p: float = 0.9
    timeout: int = 120  # seconds
    base_url: str = "http://localhost:11434"  # Ollama default
    max_retries: int = 3
    retry_delay: float = 5.0


class BaseLLMBackend(ABC):
    """Abstract base class for LLM backends."""

    def __init__(self, config: Optional[LLMConfig] = None):
        self.config = config or LLMConfig()
        self._available: Optional[bool] = None

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the backend is available and model is loaded."""
        pass

    @abstractmethod
    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> LLMResponse:
        """
        Generate text from prompt.

        Args:
            prompt: The user prompt
            system_prompt: Optional system prompt to set context

        Returns:
            LLMResponse with generated text and metadata
        """
        pass

    @abstractmethod
    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the loaded model."""
        pass

    def health_check(self) -> Dict[str, Any]:
        """Perform health check on the backend."""
        try:
            available = self.is_available()
            model_info = self.get_model_info() if available else {}
            return {
                "available": available,
                "backend": self.__class__.__name__,
                "model": self.config.model,
                "model_info": model_info,
            }
        except Exception as e:
            return {
                "available": False,
                "backend": self.__class__.__name__,
                "error": str(e),
            }

    def reset_availability_cache(self) -> None:
        """Reset the cached availability status."""
        self._available = None
