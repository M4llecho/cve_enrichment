"""
Ollama backend implementation for local LLM inference.
"""

import json
import logging
import time
from typing import Any, Dict, List, Optional

import requests

from .base import BaseLLMBackend, LLMConfig, LLMResponse

logger = logging.getLogger(__name__)


class OllamaBackend(BaseLLMBackend):
    """Ollama API backend for local LLM inference."""

    def __init__(self, config: Optional[LLMConfig] = None):
        super().__init__(config or LLMConfig())
        self.api_base = self.config.base_url.rstrip("/")

    def is_available(self) -> bool:
        """Check if Ollama is running and model is available."""
        if self._available is not None:
            return self._available

        try:
            # Check if Ollama is running
            response = requests.get(f"{self.api_base}/api/tags", timeout=5)
            response.raise_for_status()

            # Check if our model is available
            models = response.json().get("models", [])
            model_names = [m.get("name", "") for m in models]

            # Check both exact match and base name match
            target_model = self.config.model
            target_base = target_model.split(":")[0]

            self._available = any(
                target_model == name or target_base == name.split(":")[0]
                for name in model_names
            )

            if not self._available:
                logger.warning(
                    f"Model {self.config.model} not found. "
                    f"Available: {model_names}. "
                    f"Run: ollama pull {self.config.model}"
                )

            return self._available

        except requests.RequestException as e:
            logger.error(f"Ollama not available: {e}")
            self._available = False
            return False

    def generate(
        self, prompt: str, system_prompt: Optional[str] = None
    ) -> LLMResponse:
        """Generate response using Ollama API."""
        if not self.is_available():
            raise RuntimeError(
                f"Ollama backend not available. "
                f"Ensure Ollama is running (ollama serve) and model is pulled "
                f"(ollama pull {self.config.model})"
            )

        start_time = time.time()
        last_error = None

        for attempt in range(self.config.max_retries):
            try:
                payload = {
                    "model": self.config.model,
                    "prompt": prompt,
                    "stream": False,
                    "options": {
                        "temperature": self.config.temperature,
                        "top_p": self.config.top_p,
                        "num_predict": self.config.max_tokens,
                    },
                }

                if system_prompt:
                    payload["system"] = system_prompt

                response = requests.post(
                    f"{self.api_base}/api/generate",
                    json=payload,
                    timeout=self.config.timeout,
                )
                response.raise_for_status()
                result = response.json()

                generation_time = time.time() - start_time

                return LLMResponse(
                    text=result.get("response", ""),
                    model=self.config.model,
                    tokens_used=result.get("eval_count", 0),
                    generation_time=generation_time,
                    raw_response=result,
                )

            except requests.Timeout:
                last_error = f"Timeout on attempt {attempt + 1}"
                logger.warning(f"{last_error}, retrying...")
                time.sleep(self.config.retry_delay * (attempt + 1))

            except requests.RequestException as e:
                last_error = str(e)
                logger.error(f"Request failed: {e}")
                if attempt < self.config.max_retries - 1:
                    time.sleep(self.config.retry_delay * (attempt + 1))

        raise RuntimeError(f"Max retries exceeded. Last error: {last_error}")

    def get_model_info(self) -> Dict[str, Any]:
        """Get information about the loaded model."""
        try:
            response = requests.post(
                f"{self.api_base}/api/show",
                json={"name": self.config.model},
                timeout=10,
            )
            response.raise_for_status()
            return response.json()
        except requests.RequestException:
            return {}

    def list_models(self) -> List[str]:
        """List all available models."""
        try:
            response = requests.get(f"{self.api_base}/api/tags", timeout=5)
            response.raise_for_status()
            models = response.json().get("models", [])
            return [m.get("name", "") for m in models]
        except requests.RequestException:
            return []

    def pull_model(self, model_name: Optional[str] = None) -> bool:
        """
        Pull/download a model.

        Args:
            model_name: Model to pull. If None, uses configured model.

        Returns:
            True if successful
        """
        model = model_name or self.config.model
        logger.info(f"Pulling model {model}...")

        try:
            response = requests.post(
                f"{self.api_base}/api/pull",
                json={"name": model},
                timeout=3600,  # Model download can take time
                stream=True,
            )
            response.raise_for_status()

            # Stream progress
            for line in response.iter_lines():
                if line:
                    try:
                        status = json.loads(line)
                        if "status" in status:
                            logger.debug(f"Pull status: {status['status']}")
                    except json.JSONDecodeError:
                        pass

            self._available = None  # Reset cache
            return self.is_available()

        except requests.RequestException as e:
            logger.error(f"Failed to pull model: {e}")
            return False

    def check_gpu_usage(self) -> Dict[str, Any]:
        """Check if GPU is being used for inference."""
        try:
            response = requests.get(f"{self.api_base}/api/ps", timeout=5)
            response.raise_for_status()
            return response.json()
        except requests.RequestException:
            return {"error": "Could not check GPU status"}
