"""
CVE Tagger - Main class for LLM-based CVE tagging.

This class orchestrates the tagging process:
1. Takes enriched CVE data
2. Builds a prompt with all available information
3. Calls the LLM backend
4. Parses and validates the response
5. Returns structured tag data
"""

import json
import logging
import re
import time
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional

from .base import BaseLLMBackend, LLMConfig
from .config import LLMTaggerConfig, DEFAULT_CONFIG
from .ollama_backend import OllamaBackend
from .prompts import SYSTEM_PROMPT, build_cve_analysis_prompt
from .taxonomy import TAXONOMY_VERSION, validate_tags_by_category
from .validator import validate_tag_coherence

logger = logging.getLogger(__name__)


class CVETagger:
    """
    CVE Tagger using local LLM for security tag assignment.

    Example usage:
        tagger = CVETagger()
        if tagger.is_available():
            result = tagger.tag_cve(enriched_cve_data)
    """

    def __init__(
        self,
        backend: Optional[BaseLLMBackend] = None,
        config: Optional[LLMTaggerConfig] = None,
    ):
        """
        Initialize the CVE Tagger.

        Args:
            backend: LLM backend to use. If None, creates OllamaBackend.
            config: Tagger configuration. If None, uses defaults.
        """
        self.config = config or DEFAULT_CONFIG
        self.backend = backend or OllamaBackend(self.config.to_llm_config())
        self._stats = {
            "tagged_count": 0,
            "failed_count": 0,
            "total_time": 0.0,
        }

    def is_available(self) -> bool:
        """Check if the tagger is ready to use."""
        return self.backend.is_available()

    def health_check(self) -> Dict[str, Any]:
        """Perform health check on the tagger."""
        return {
            "backend": self.backend.health_check(),
            "taxonomy_version": TAXONOMY_VERSION,
            "config": {
                "model": self.config.model,
                "backend": self.config.backend,
            },
            "stats": self._stats.copy(),
        }

    def tag_cve(self, cve_data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        Tag a single CVE with security tags.

        Args:
            cve_data: Enriched CVE data dictionary

        Returns:
            Dictionary with tags and metadata, or None if failed
        """
        cve_id = cve_data.get("cve_id", "Unknown")

        if not self.is_available():
            logger.warning(f"LLM not available - skipping tagging for {cve_id}")
            return None

        try:
            start_time = time.time()

            # Build prompt
            prompt = build_cve_analysis_prompt(cve_data)

            # Generate response
            response = self.backend.generate(prompt, SYSTEM_PROMPT)

            # Parse response
            tags = self._parse_response(response.text)

            if tags is None:
                logger.warning(f"Failed to parse LLM response for {cve_id}")
                self._stats["failed_count"] += 1
                return None

            # Validate tags against taxonomy
            validated_tags = validate_tags_by_category(tags)

            # Apply coherence validation with CVSS context
            cvss_vector = cve_data.get("cvss_vector")
            coherent_tags = validate_tag_coherence(validated_tags, cvss_vector)

            # Build result (no confidence - it was LLM self-generated and unreliable)
            result = {
                "cve_id": cve_id,
                "llm_tags_version": TAXONOMY_VERSION,
                "llm_model_used": self.config.model,
                "llm_tagged_at": datetime.now(),
                "kill_chain_phases": coherent_tags.get("kill_chain_phases", []),
                "prerequisites": coherent_tags.get("prerequisites", []),
                "capabilities": coherent_tags.get("capabilities", []),
            }

            elapsed = time.time() - start_time
            self._stats["tagged_count"] += 1
            self._stats["total_time"] += elapsed

            logger.debug(
                f"Tagged {cve_id} in {elapsed:.2f}s: "
                f"phases={result['kill_chain_phases']}, "
                f"prereq={result['prerequisites']}, "
                f"caps={result['capabilities']}"
            )

            return result

        except Exception as e:
            logger.error(f"Error tagging {cve_id}: {e}")
            self._stats["failed_count"] += 1
            return None

    def tag_cves_batch(
        self,
        cve_list: List[Dict[str, Any]],
        progress_callback: Optional[Callable[[int, int], None]] = None,
    ) -> List[Dict[str, Any]]:
        """
        Tag multiple CVEs.

        Args:
            cve_list: List of enriched CVE data dictionaries
            progress_callback: Optional callback(current, total) for progress

        Returns:
            List of tagging results (successful ones only)
        """
        results = []
        total = len(cve_list)

        for i, cve_data in enumerate(cve_list):
            result = self.tag_cve(cve_data)
            if result:
                results.append(result)

            if progress_callback:
                progress_callback(i + 1, total)

        return results

    def _parse_response(self, response_text: str) -> Optional[Dict[str, Any]]:
        """
        Parse LLM response to extract tags.

        Handles various response formats including DeepSeek-R1 reasoning tags.
        """
        text = response_text.strip()

        # Pre-process: Remove DeepSeek-R1 <think>...</think> reasoning tags
        # These models output reasoning before the JSON
        think_pattern = re.compile(r"<think>.*?</think>", re.DOTALL | re.IGNORECASE)
        text = think_pattern.sub("", text).strip()

        # Also handle unclosed <think> tags (model cut off)
        if "<think>" in text.lower():
            think_start = text.lower().find("<think>")
            # Find JSON after the think section
            json_after_think = text.find("{", think_start)
            if json_after_think >= 0:
                text = text[json_after_think:]
            else:
                # No JSON found after think, try to find it before
                text = text[:think_start].strip()

        # Strategy 1: Direct JSON parse
        try:
            data = json.loads(text)
            return self._normalize_parsed_data(data)
        except json.JSONDecodeError:
            pass

        # Strategy 2: Extract JSON from markdown code block
        json_match = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
        if json_match:
            try:
                data = json.loads(json_match.group(1))
                return self._normalize_parsed_data(data)
            except json.JSONDecodeError:
                pass

        # Strategy 3: Find any JSON object in text (handles text before/after JSON)
        json_start = text.find("{")
        if json_start >= 0:
            # Find matching closing brace
            brace_count = 0
            json_end = -1
            for i, char in enumerate(text[json_start:], start=json_start):
                if char == "{":
                    brace_count += 1
                elif char == "}":
                    brace_count -= 1
                    if brace_count == 0:
                        json_end = i + 1
                        break

            if json_end > json_start:
                try:
                    data = json.loads(text[json_start:json_end])
                    return self._normalize_parsed_data(data)
                except json.JSONDecodeError:
                    pass

        # Strategy 4: Last resort - find first { to last }
        json_end = text.rfind("}") + 1
        if json_start >= 0 and json_end > json_start:
            try:
                data = json.loads(text[json_start:json_end])
                return self._normalize_parsed_data(data)
            except json.JSONDecodeError:
                pass

        # All strategies failed
        logger.debug(f"Could not parse response: {text[:200]}...")
        return None

    def _normalize_parsed_data(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Normalize parsed data to expected format."""
        expected_keys = ["kill_chain_phases", "prerequisites", "capabilities"]

        for key in expected_keys:
            if key not in data:
                data[key] = []
            elif not isinstance(data[key], list):
                # Convert single value to list
                data[key] = [data[key]] if data[key] else []

        return data

    def get_stats(self) -> Dict[str, Any]:
        """Get tagging statistics."""
        stats = self._stats.copy()
        if stats["tagged_count"] > 0:
            stats["avg_time_per_cve"] = stats["total_time"] / stats["tagged_count"]
        else:
            stats["avg_time_per_cve"] = 0.0
        return stats

    def reset_stats(self) -> None:
        """Reset tagging statistics."""
        self._stats = {
            "tagged_count": 0,
            "failed_count": 0,
            "total_time": 0.0,
        }
