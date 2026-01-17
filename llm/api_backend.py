"""
Cloud API backend for LLM inference.

Supports: Gemini, DeepSeek, OpenAI, Anthropic.
"""

import json
import logging
import os
import time
from typing import Any, Dict, Optional

import requests

from .base import BaseLLMBackend, LLMConfig, LLMResponse

logger = logging.getLogger(__name__)


# Provider-specific defaults
PROVIDER_DEFAULTS = {
    "gemini": {
        "base_url": "https://generativelanguage.googleapis.com/v1beta",
        "model": "gemini-2.5-flash",
    },
    "deepseek": {
        "base_url": "https://api.deepseek.com/v1",
        "model": "deepseek-chat",
    },
    "openai": {
        "base_url": "https://api.openai.com/v1",
        "model": "gpt-4o",
    },
    "anthropic": {
        "base_url": "https://api.anthropic.com/v1",
        "model": "claude-3-5-haiku-latest",
    },
    "groq": {
        "base_url": "https://api.groq.com/openai/v1",
        "model": "llama-3.3-70b-versatile",
    },
}

# Pricing per million tokens (input, output)
PRICING = {
    "gemini-2.5-flash-lite": (0.10, 0.40),
    "gemini-2.5-flash": (0.15, 0.60),
    "gemini-2.5-pro": (1.25, 10.00),
    "deepseek-chat": (0.28, 0.42),
    "deepseek-reasoner": (0.28, 0.42),
    "gpt-4o": (2.50, 10.00),
    "gpt-4o-mini": (0.15, 0.60),
    "claude-3-5-haiku-latest": (0.80, 4.00),
    "claude-3-5-sonnet-latest": (3.00, 15.00),
    "llama-3.3-70b-versatile": (0.59, 0.79),
}


class APIBackend(BaseLLMBackend):
    """Cloud API backend for LLM inference."""

    def __init__(
        self,
        provider: str = "gemini",
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        config: Optional[LLMConfig] = None,
    ):
        """
        Initialize API backend.

        Args:
            provider: API provider (gemini, deepseek, openai, anthropic, groq)
            api_key: API key (or use environment variable)
            model: Model name (or use provider default)
            config: LLM configuration
        """
        super().__init__(config or LLMConfig())

        self.provider = provider.lower()
        if self.provider not in PROVIDER_DEFAULTS:
            raise ValueError(
                f"Unknown provider: {provider}. "
                f"Supported: {list(PROVIDER_DEFAULTS.keys())}"
            )

        # Get provider defaults
        defaults = PROVIDER_DEFAULTS[self.provider]
        self.base_url = defaults["base_url"]
        self.config.model = model or defaults["model"]

        # Get API key from parameter or environment
        env_key_name = f"{self.provider.upper()}_API_KEY"
        self.api_key = api_key or os.getenv(env_key_name)
        if not self.api_key:
            logger.warning(
                f"No API key provided. Set {env_key_name} environment variable "
                f"or pass api_key parameter."
            )

        # Stats tracking
        self._stats = {
            "total_requests": 0,
            "total_input_tokens": 0,
            "total_output_tokens": 0,
            "total_cost": 0.0,
            "total_time": 0.0,
        }

    def is_available(self) -> bool:
        """Check if API is available."""
        if self._available is not None:
            return self._available

        if not self.api_key:
            self._available = False
            return False

        try:
            # Simple validation - different per provider
            if self.provider == "gemini":
                response = requests.get(
                    f"{self.base_url}/models?key={self.api_key}",
                    timeout=10,
                )
            elif self.provider in ("openai", "deepseek", "groq"):
                response = requests.get(
                    f"{self.base_url}/models",
                    headers={"Authorization": f"Bearer {self.api_key}"},
                    timeout=10,
                )
            elif self.provider == "anthropic":
                # Anthropic doesn't have a models endpoint, just check key format
                self._available = len(self.api_key) > 20
                return self._available
            else:
                self._available = True
                return True

            self._available = response.status_code == 200
            return self._available

        except requests.RequestException as e:
            logger.error(f"API not available: {e}")
            self._available = False
            return False

    def generate(
        self, prompt: str, system_prompt: Optional[str] = None
    ) -> LLMResponse:
        """Generate response using cloud API."""
        if not self.api_key:
            raise RuntimeError(
                f"No API key configured for {self.provider}. "
                f"Set {self.provider.upper()}_API_KEY environment variable."
            )

        start_time = time.time()
        last_error = None

        for attempt in range(self.config.max_retries):
            try:
                if self.provider == "gemini":
                    result = self._call_gemini(prompt, system_prompt)
                elif self.provider == "deepseek":
                    result = self._call_openai_compatible(prompt, system_prompt)
                elif self.provider == "openai":
                    result = self._call_openai_compatible(prompt, system_prompt)
                elif self.provider == "anthropic":
                    result = self._call_anthropic(prompt, system_prompt)
                elif self.provider == "groq":
                    result = self._call_openai_compatible(prompt, system_prompt)
                else:
                    raise ValueError(f"Unknown provider: {self.provider}")

                generation_time = time.time() - start_time

                # Update stats
                self._stats["total_requests"] += 1
                self._stats["total_input_tokens"] += result.get("input_tokens", 0)
                self._stats["total_output_tokens"] += result.get("output_tokens", 0)
                self._stats["total_time"] += generation_time
                self._update_cost(result.get("input_tokens", 0), result.get("output_tokens", 0))

                return LLMResponse(
                    text=result["text"],
                    model=self.config.model,
                    tokens_used=result.get("input_tokens", 0) + result.get("output_tokens", 0),
                    generation_time=generation_time,
                    raw_response=result.get("raw_response"),
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

    def _call_gemini(self, prompt: str, system_prompt: Optional[str]) -> Dict[str, Any]:
        """Call Gemini API."""
        url = f"{self.base_url}/models/{self.config.model}:generateContent?key={self.api_key}"

        contents = []
        if system_prompt:
            contents.append({
                "role": "user",
                "parts": [{"text": f"System: {system_prompt}"}]
            })
            contents.append({
                "role": "model",
                "parts": [{"text": "Understood. I will follow these instructions."}]
            })

        contents.append({
            "role": "user",
            "parts": [{"text": prompt}]
        })

        payload = {
            "contents": contents,
            "generationConfig": {
                "temperature": 0.0,      # Deterministico per tag consistenti
                "topP": 0.95,
                "topK": 40,
                "maxOutputTokens": 512,  # JSON output ~60 token
                "responseMimeType": "application/json",  # Forza JSON pulito
            },
        }

        response = requests.post(url, json=payload, timeout=self.config.timeout)
        response.raise_for_status()
        data = response.json()

        text = ""
        if "candidates" in data and data["candidates"]:
            parts = data["candidates"][0].get("content", {}).get("parts", [])
            text = "".join(p.get("text", "") for p in parts)

        usage = data.get("usageMetadata", {})
        return {
            "text": text,
            "input_tokens": usage.get("promptTokenCount", 0),
            "output_tokens": usage.get("candidatesTokenCount", 0),
            "raw_response": data,
        }

    def _call_openai_compatible(self, prompt: str, system_prompt: Optional[str]) -> Dict[str, Any]:
        """Call OpenAI-compatible API (OpenAI, DeepSeek, Groq)."""
        url = f"{self.base_url}/chat/completions"

        messages = []
        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        messages.append({"role": "user", "content": prompt})

        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": min(self.config.max_tokens, 4096),
        }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        response = requests.post(
            url, json=payload, headers=headers, timeout=self.config.timeout
        )
        response.raise_for_status()
        data = response.json()

        text = ""
        if "choices" in data and data["choices"]:
            text = data["choices"][0].get("message", {}).get("content", "")

        usage = data.get("usage", {})
        return {
            "text": text,
            "input_tokens": usage.get("prompt_tokens", 0),
            "output_tokens": usage.get("completion_tokens", 0),
            "raw_response": data,
        }

    def _call_anthropic(self, prompt: str, system_prompt: Optional[str]) -> Dict[str, Any]:
        """Call Anthropic API."""
        url = f"{self.base_url}/messages"

        payload = {
            "model": self.config.model,
            "max_tokens": min(self.config.max_tokens, 4096),
            "messages": [{"role": "user", "content": prompt}],
        }

        if system_prompt:
            payload["system"] = system_prompt

        headers = {
            "x-api-key": self.api_key,
            "anthropic-version": "2023-06-01",
            "Content-Type": "application/json",
        }

        response = requests.post(
            url, json=payload, headers=headers, timeout=self.config.timeout
        )
        response.raise_for_status()
        data = response.json()

        text = ""
        if "content" in data and data["content"]:
            text = "".join(
                block.get("text", "") for block in data["content"]
                if block.get("type") == "text"
            )

        usage = data.get("usage", {})
        return {
            "text": text,
            "input_tokens": usage.get("input_tokens", 0),
            "output_tokens": usage.get("output_tokens", 0),
            "raw_response": data,
        }

    def _update_cost(self, input_tokens: int, output_tokens: int) -> None:
        """Update cost estimate based on token usage."""
        pricing = PRICING.get(self.config.model)
        if pricing:
            input_price, output_price = pricing
            cost = (input_tokens * input_price + output_tokens * output_price) / 1_000_000
            self._stats["total_cost"] += cost

    def get_model_info(self) -> Dict[str, Any]:
        """Get model information."""
        return {
            "provider": self.provider,
            "model": self.config.model,
            "base_url": self.base_url,
            "pricing": PRICING.get(self.config.model, "unknown"),
        }

    def get_stats(self) -> Dict[str, Any]:
        """Get usage statistics."""
        stats = self._stats.copy()
        if stats["total_requests"] > 0:
            stats["avg_time_per_request"] = stats["total_time"] / stats["total_requests"]
            stats["avg_tokens_per_request"] = (
                (stats["total_input_tokens"] + stats["total_output_tokens"])
                / stats["total_requests"]
            )
        return stats

    def reset_stats(self) -> None:
        """Reset usage statistics."""
        self._stats = {
            "total_requests": 0,
            "total_input_tokens": 0,
            "total_output_tokens": 0,
            "total_cost": 0.0,
            "total_time": 0.0,
        }

    def estimate_cost(self, num_cves: int, tokens_per_cve: int = 1600) -> Dict[str, float]:
        """
        Estimate cost for tagging CVEs.

        Args:
            num_cves: Number of CVEs to tag
            tokens_per_cve: Estimated tokens per CVE (input + output)

        Returns:
            Cost estimates per provider
        """
        # Assume 1500 input + 100 output tokens per CVE
        input_tokens = num_cves * 1500
        output_tokens = num_cves * 100

        estimates = {}
        for model, (input_price, output_price) in PRICING.items():
            cost = (input_tokens * input_price + output_tokens * output_price) / 1_000_000
            estimates[model] = round(cost, 2)

        return estimates
