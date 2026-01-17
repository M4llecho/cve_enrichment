"""
Asynchronous Gemini API Backend for high-throughput CVE tagging.

Features:
- Async/await for parallel requests
- Rate limiting (RPM, TPM, RPD)
- Exponential backoff with tenacity
- Context caching for reduced costs
"""

import asyncio
import json
import logging
import os
import re
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

import aiohttp


@dataclass
class GeminiPricing:
    """
    Gemini API pricing per million tokens (as of Jan 2025).

    Source: https://ai.google.dev/gemini-api/docs/pricing
    """
    # Gemini 2.5 Flash Standard Tier
    input_per_mtok: float = 0.30        # $0.30 per 1M input tokens
    output_per_mtok: float = 2.50       # $2.50 per 1M output tokens
    cached_input_per_mtok: float = 0.03 # $0.03 per 1M cached input tokens (90% discount)
    cache_storage_per_mtok_hour: float = 1.00  # $1.00 per 1M tokens per hour storage

    def calculate_cost(
        self,
        input_tokens: int,
        output_tokens: int,
        cached_tokens: int = 0,
        cache_hours: float = 0.0,
        cache_size_tokens: int = 0,
    ) -> Dict[str, float]:
        """Calculate detailed cost breakdown."""
        # Non-cached input cost
        non_cached_input = input_tokens - cached_tokens
        input_cost = (non_cached_input / 1_000_000) * self.input_per_mtok

        # Cached input cost (90% cheaper)
        cached_cost = (cached_tokens / 1_000_000) * self.cached_input_per_mtok

        # Output cost
        output_cost = (output_tokens / 1_000_000) * self.output_per_mtok

        # Cache storage cost (per hour)
        storage_cost = (cache_size_tokens / 1_000_000) * self.cache_storage_per_mtok_hour * cache_hours

        total = input_cost + cached_cost + output_cost + storage_cost

        # Calculate savings from caching
        savings = (cached_tokens / 1_000_000) * (self.input_per_mtok - self.cached_input_per_mtok)

        return {
            "input_cost": input_cost,
            "cached_cost": cached_cost,
            "output_cost": output_cost,
            "storage_cost": storage_cost,
            "total_cost": total,
            "savings_from_cache": savings,
        }
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
)

from .rate_limiter import GeminiRateLimiter, get_rate_limiter
from .prompts_api import API_SYSTEM_PROMPT, build_api_analysis_prompt
from .taxonomy import TAXONOMY_VERSION, validate_tags_by_category
from .validator import validate_tag_coherence

logger = logging.getLogger(__name__)


@dataclass
class AsyncTagResult:
    """Result from async tagging operation."""
    cve_id: str
    success: bool
    tags: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    tokens_used: int = 0
    generation_time: float = 0.0


class AsyncGeminiBackend:
    """
    Asynchronous backend for Gemini API with rate limiting and caching.

    Usage:
        async with AsyncGeminiBackend() as backend:
            results = await backend.tag_cves_batch(cve_list, concurrency=10)
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: str = "gemini-2.5-flash",
        rate_limiter: Optional[GeminiRateLimiter] = None,
    ):
        """
        Initialize async Gemini backend.

        Args:
            api_key: Gemini API key (or uses GEMINI_API_KEY env var)
            model: Model name (default: gemini-2.5-pro)
            rate_limiter: Custom rate limiter (or uses default singleton)
        """
        self.api_key = api_key or os.getenv("GEMINI_API_KEY")
        if not self.api_key:
            raise ValueError("GEMINI_API_KEY environment variable not set")

        self.model = model
        self.base_url = "https://generativelanguage.googleapis.com/v1beta"
        self.rate_limiter = rate_limiter or get_rate_limiter()

        self._session: Optional[aiohttp.ClientSession] = None
        self._cached_context_name: Optional[str] = None
        self._cache_created_at: Optional[datetime] = None
        self._cache_token_count: int = 0

        # Pricing calculator
        self._pricing = GeminiPricing()

        # Detailed stats
        self._stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "retries": 0,
            "total_time": 0.0,
            # Token breakdown
            "input_tokens": 0,
            "output_tokens": 0,
            "cached_tokens": 0,
            "total_tokens": 0,
            # Timing stats
            "min_response_time": float('inf'),
            "max_response_time": 0.0,
            # For cost calculation
            "cache_hits": 0,
        }

    async def __aenter__(self):
        """Async context manager entry."""
        connector = aiohttp.TCPConnector(limit=100)  # Connection pool
        timeout = aiohttp.ClientTimeout(total=60)
        self._session = aiohttp.ClientSession(connector=connector, timeout=timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self._session:
            await self._session.close()
        # Clean up cached context if exists
        if self._cached_context_name:
            await self._delete_cached_context()

    async def create_context_cache(self, system_prompt: str, ttl_seconds: int = 3600) -> str:
        """
        Create a cached context for the system prompt.
        Reduces costs by caching the static instructions.

        Args:
            system_prompt: System prompt to cache
            ttl_seconds: Cache TTL in seconds (default: 1 hour)

        Returns:
            Cache name for use in subsequent requests
        """
        # Don't recreate if already cached
        if self._cached_context_name:
            logger.debug(f"Context cache already exists: {self._cached_context_name}")
            return self._cached_context_name

        url = f"{self.base_url}/cachedContents?key={self.api_key}"

        payload = {
            "model": f"models/{self.model}",
            "contents": [
                {"role": "user", "parts": [{"text": f"System: {system_prompt}"}]},
                {"role": "model", "parts": [{"text": "Understood. I will follow these instructions and respond with JSON only."}]},
            ],
            "ttl": f"{ttl_seconds}s",
        }

        async with self._session.post(url, json=payload) as response:
            if response.status == 200:
                data = await response.json()
                self._cached_context_name = data.get("name")
                self._cache_created_at = datetime.now()
                # Extract token count from cache metadata
                usage = data.get("usageMetadata", {})
                self._cache_token_count = usage.get("totalTokenCount", 0)
                logger.info(
                    f"Created context cache: {self._cached_context_name} "
                    f"({self._cache_token_count:,} tokens)"
                )
                return self._cached_context_name
            else:
                # Context cache may fail if prompt is too small - this is OK, we continue without caching
                error_data = await response.json()
                if error_data.get("error", {}).get("code") == 400:
                    logger.debug(f"Context cache not created (prompt too small), continuing without cache")
                else:
                    logger.warning(f"Failed to create context cache: {error_data}")
                return None

    async def _delete_cached_context(self) -> None:
        """Delete the cached context when done."""
        if not self._cached_context_name:
            return

        url = f"{self.base_url}/{self._cached_context_name}?key={self.api_key}"
        try:
            async with self._session.delete(url) as response:
                if response.status == 200:
                    logger.info(f"Deleted context cache: {self._cached_context_name}")
        except Exception as e:
            logger.warning(f"Failed to delete context cache: {e}")

    @retry(
        stop=stop_after_attempt(5),
        wait=wait_exponential(multiplier=1, min=1, max=60),
        retry=retry_if_exception_type((aiohttp.ClientError, asyncio.TimeoutError)),
        before_sleep=before_sleep_log(logger, logging.WARNING),
    )
    async def _call_api(self, prompt: str, system_prompt: str) -> Dict[str, Any]:
        """
        Call Gemini API with retry logic.

        Args:
            prompt: User prompt
            system_prompt: System instructions

        Returns:
            Parsed API response
        """
        await self.rate_limiter.acquire(estimated_tokens=2000)

        url = f"{self.base_url}/models/{self.model}:generateContent?key={self.api_key}"

        # Build payload - use cached context if available
        if self._cached_context_name:
            payload = {
                "cachedContent": self._cached_context_name,
                "contents": [{"role": "user", "parts": [{"text": prompt}]}],
                "generationConfig": {
                    "temperature": 0.0,
                    "topP": 0.95,
                    "topK": 40,
                    "maxOutputTokens": 8192,
                    "responseMimeType": "application/json",
                },
            }
        else:
            # Build full payload with system prompt
            contents = [
                {"role": "user", "parts": [{"text": f"System: {system_prompt}"}]},
                {"role": "model", "parts": [{"text": "Understood. I will respond with JSON only."}]},
                {"role": "user", "parts": [{"text": prompt}]},
            ]
            payload = {
                "contents": contents,
                "generationConfig": {
                    "temperature": 0.0,
                    "topP": 0.95,
                    "topK": 40,
                    "maxOutputTokens": 8192,
                    "responseMimeType": "application/json",
                },
            }

        async with self._session.post(url, json=payload) as response:
            if response.status == 429:
                # Rate limited by API
                retry_after = int(response.headers.get("Retry-After", 5))
                logger.warning(f"Rate limited by API, waiting {retry_after}s")
                self._stats["retries"] += 1
                await asyncio.sleep(retry_after)
                raise aiohttp.ClientError("Rate limited by API")

            if response.status != 200:
                error_text = await response.text()
                raise aiohttp.ClientError(f"API error {response.status}: {error_text[:200]}")

            data = await response.json()

        # Update rate limiter with actual tokens
        usage = data.get("usageMetadata", {})
        actual_tokens = usage.get("promptTokenCount", 0) + usage.get("candidatesTokenCount", 0)
        self.rate_limiter.update_tokens(actual_tokens)

        return data

    def _parse_response(self, data: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse Gemini API response to extract tags."""
        if "candidates" not in data or not data["candidates"]:
            logger.warning(f"No candidates in response: {json.dumps(data)[:500]}")
            return None

        # Check for safety block or other finish reasons
        candidate = data["candidates"][0]
        finish_reason = candidate.get("finishReason", "")
        if finish_reason and finish_reason not in ("STOP", "MAX_TOKENS"):
            logger.warning(f"Unexpected finishReason: {finish_reason}")

        parts = candidate.get("content", {}).get("parts", [])
        text = "".join(p.get("text", "") for p in parts).strip()

        if not text:
            logger.warning(f"Empty text in response. Candidate: {json.dumps(candidate)[:500]}")
            return None

        # Try to parse JSON
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            # Try to extract JSON from markdown
            json_match = re.search(r"```(?:json)?\s*(.*?)\s*```", text, re.DOTALL)
            if json_match:
                try:
                    return json.loads(json_match.group(1))
                except json.JSONDecodeError:
                    pass

            # Try to find JSON object in text
            json_start = text.find("{")
            json_end = text.rfind("}") + 1
            if json_start >= 0 and json_end > json_start:
                try:
                    return json.loads(text[json_start:json_end])
                except json.JSONDecodeError:
                    pass

        logger.warning(f"Failed to parse response: {text[:200]}")
        return None

    async def tag_cve(self, cve_data: Dict[str, Any]) -> AsyncTagResult:
        """
        Tag a single CVE.

        Args:
            cve_data: Enriched CVE data dictionary

        Returns:
            AsyncTagResult with tags or error
        """
        cve_id = cve_data.get("cve_id", "Unknown")
        start_time = asyncio.get_event_loop().time()

        try:
            # Build prompt
            prompt = build_api_analysis_prompt(cve_data)

            # Call API
            response_data = await self._call_api(prompt, API_SYSTEM_PROMPT)

            # Parse response
            tags = self._parse_response(response_data)

            if tags is None:
                self._stats["failed_requests"] += 1
                return AsyncTagResult(
                    cve_id=cve_id,
                    success=False,
                    error="Failed to parse response",
                )

            # Validate tags
            validated_tags = validate_tags_by_category(tags)

            # Apply coherence validation
            cvss_vector = cve_data.get("cvss_vector")
            coherent_tags = validate_tag_coherence(validated_tags, cvss_vector)

            # Extract confidence
            confidence = tags.get("confidence")
            if confidence is not None:
                try:
                    confidence = float(confidence)
                    confidence = max(0.0, min(1.0, confidence))
                except (TypeError, ValueError):
                    confidence = None

            # Get detailed token usage
            usage = response_data.get("usageMetadata", {})
            input_tokens = usage.get("promptTokenCount", 0)
            output_tokens = usage.get("candidatesTokenCount", 0)
            cached_tokens = usage.get("cachedContentTokenCount", 0)
            tokens_used = input_tokens + output_tokens

            generation_time = asyncio.get_event_loop().time() - start_time

            # Update detailed stats
            self._stats["total_requests"] += 1
            self._stats["successful_requests"] += 1
            self._stats["input_tokens"] += input_tokens
            self._stats["output_tokens"] += output_tokens
            self._stats["cached_tokens"] += cached_tokens
            self._stats["total_tokens"] += tokens_used
            self._stats["total_time"] += generation_time
            self._stats["min_response_time"] = min(self._stats["min_response_time"], generation_time)
            self._stats["max_response_time"] = max(self._stats["max_response_time"], generation_time)
            if cached_tokens > 0:
                self._stats["cache_hits"] += 1

            return AsyncTagResult(
                cve_id=cve_id,
                success=True,
                tags={
                    "cve_id": cve_id,
                    "llm_tags_version": TAXONOMY_VERSION,
                    "llm_model_used": self.model,
                    "llm_tagged_at": datetime.now(),
                    "llm_confidence_score": confidence,
                    "kill_chain_phases": coherent_tags.get("kill_chain_phases", []),
                    "prerequisites": coherent_tags.get("prerequisites", []),
                    "capabilities": coherent_tags.get("capabilities", []),
                },
                tokens_used=tokens_used,
                generation_time=generation_time,
            )

        except Exception as e:
            self._stats["total_requests"] += 1
            self._stats["failed_requests"] += 1
            logger.error(f"Error tagging {cve_id}: {e}")
            return AsyncTagResult(
                cve_id=cve_id,
                success=False,
                error=str(e),
            )

    async def tag_cves_batch(
        self,
        cve_list: List[Dict[str, Any]],
        concurrency: int = 10,
        use_context_cache: bool = True,
    ) -> List[AsyncTagResult]:
        """
        Tag multiple CVEs with controlled concurrency.

        Args:
            cve_list: List of enriched CVE data dictionaries
            concurrency: Maximum concurrent requests
            use_context_cache: Whether to use context caching (reduces costs)

        Returns:
            List of AsyncTagResult for each CVE
        """
        # Create context cache for system prompt if enabled
        if use_context_cache:
            await self.create_context_cache(API_SYSTEM_PROMPT, ttl_seconds=3600)

        # Semaphore for concurrency control
        semaphore = asyncio.Semaphore(concurrency)

        # Stagger delay to avoid burst (spread requests over time)
        # Target: ~16 req/s to stay under 1000 RPM
        stagger_delay = 1.0 / 16.0  # ~62ms between request starts

        async def process_with_semaphore(cve_data: Dict[str, Any], index: int) -> AsyncTagResult:
            # Stagger initial requests to avoid burst
            if index < concurrency * 2:  # First 2 waves get staggered
                await asyncio.sleep(index * stagger_delay)
            async with semaphore:
                return await self.tag_cve(cve_data)

        # Create tasks with index for staggering
        tasks = [process_with_semaphore(cve, i) for i, cve in enumerate(cve_list)]

        # Run with progress tracking
        results = await asyncio.gather(*tasks, return_exceptions=True)

        # Convert exceptions to error results
        final_results = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                final_results.append(AsyncTagResult(
                    cve_id=cve_list[i].get("cve_id", "Unknown"),
                    success=False,
                    error=str(result),
                ))
            else:
                final_results.append(result)

        return final_results

    def get_stats(self) -> Dict[str, Any]:
        """Get detailed tagging statistics."""
        stats = self._stats.copy()
        if stats["total_requests"] > 0:
            stats["success_rate"] = stats["successful_requests"] / stats["total_requests"]
            stats["avg_tokens_per_request"] = stats["total_tokens"] / stats["total_requests"]
            stats["avg_input_tokens"] = stats["input_tokens"] / stats["total_requests"]
            stats["avg_output_tokens"] = stats["output_tokens"] / stats["total_requests"]
            stats["avg_time_per_request"] = stats["total_time"] / stats["total_requests"]
            stats["cache_hit_rate"] = stats["cache_hits"] / stats["total_requests"] if stats["total_requests"] > 0 else 0
        # Fix infinity for min_response_time when no requests
        if stats["min_response_time"] == float('inf'):
            stats["min_response_time"] = 0.0
        stats["rate_limiter"] = self.rate_limiter.get_stats()
        stats["model"] = self.model
        return stats

    def get_cost_summary(self) -> Dict[str, Any]:
        """
        Get detailed cost breakdown.

        Returns dict with:
        - Token counts (input, output, cached)
        - Cost breakdown (input, output, cache, storage)
        - Total cost and savings
        - Projections (cost per 1000 CVE, per 100K CVE)
        """
        stats = self._stats

        # Calculate cache duration
        cache_hours = 0.0
        if self._cache_created_at:
            cache_hours = (datetime.now() - self._cache_created_at).total_seconds() / 3600

        # Calculate costs using pricing model
        costs = self._pricing.calculate_cost(
            input_tokens=stats["input_tokens"],
            output_tokens=stats["output_tokens"],
            cached_tokens=stats["cached_tokens"],
            cache_hours=cache_hours,
            cache_size_tokens=self._cache_token_count,
        )

        # Calculate per-CVE metrics
        cve_count = stats["successful_requests"]
        if cve_count > 0:
            cost_per_cve = costs["total_cost"] / cve_count
            tokens_per_cve = stats["total_tokens"] / cve_count

            # Projections
            cost_per_1k = cost_per_cve * 1_000
            cost_per_100k = cost_per_cve * 100_000
        else:
            cost_per_cve = 0
            tokens_per_cve = 0
            cost_per_1k = 0
            cost_per_100k = 0

        return {
            # Token breakdown
            "input_tokens": stats["input_tokens"],
            "output_tokens": stats["output_tokens"],
            "cached_tokens": stats["cached_tokens"],
            "total_tokens": stats["total_tokens"],
            # Cost breakdown (in USD)
            "input_cost": costs["input_cost"],
            "cached_cost": costs["cached_cost"],
            "output_cost": costs["output_cost"],
            "storage_cost": costs["storage_cost"],
            "total_cost": costs["total_cost"],
            "savings_from_cache": costs["savings_from_cache"],
            # Per-CVE metrics
            "cost_per_cve": cost_per_cve,
            "tokens_per_cve": tokens_per_cve,
            # Projections
            "cost_per_1k_cve": cost_per_1k,
            "cost_per_100k_cve": cost_per_100k,
            # Cache info
            "cache_active": self._cached_context_name is not None,
            "cache_tokens": self._cache_token_count,
            "cache_hours": cache_hours,
            # Model info
            "model": self.model,
            "pricing": {
                "input_per_mtok": self._pricing.input_per_mtok,
                "output_per_mtok": self._pricing.output_per_mtok,
                "cached_per_mtok": self._pricing.cached_input_per_mtok,
            },
        }

    def format_cost_report(self) -> str:
        """Format a human-readable cost report."""
        cost = self.get_cost_summary()
        stats = self.get_stats()

        lines = [
            "=" * 60,
            "GEMINI API COST REPORT",
            "=" * 60,
            f"Model: {cost['model']}",
            f"CVEs processed: {stats['successful_requests']:,}",
            f"Success rate: {stats.get('success_rate', 0) * 100:.1f}%",
            "",
            "TOKEN USAGE:",
            f"  Input tokens:  {cost['input_tokens']:>12,}",
            f"  Output tokens: {cost['output_tokens']:>12,}",
            f"  Cached tokens: {cost['cached_tokens']:>12,}",
            f"  Total tokens:  {cost['total_tokens']:>12,}",
            "",
            "COST BREAKDOWN:",
            f"  Input cost:    ${cost['input_cost']:>10.4f}",
            f"  Cached cost:   ${cost['cached_cost']:>10.4f}",
            f"  Output cost:   ${cost['output_cost']:>10.4f}",
            f"  Storage cost:  ${cost['storage_cost']:>10.4f}",
            f"  ─────────────────────────",
            f"  TOTAL COST:    ${cost['total_cost']:>10.4f}",
            f"  Savings:       ${cost['savings_from_cache']:>10.4f} (from cache)",
            "",
            "PER-CVE METRICS:",
            f"  Cost per CVE:     ${cost['cost_per_cve']:.6f}",
            f"  Tokens per CVE:   {cost['tokens_per_cve']:.0f}",
            f"  Avg response:     {stats.get('avg_time_per_request', 0):.2f}s",
            "",
            "PROJECTIONS:",
            f"  Cost per 1K CVE:   ${cost['cost_per_1k_cve']:.2f}",
            f"  Cost per 100K CVE: ${cost['cost_per_100k_cve']:.2f}",
            "=" * 60,
        ]
        return "\n".join(lines)

    def reset_stats(self) -> None:
        """Reset statistics."""
        self._stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "retries": 0,
            "total_time": 0.0,
            "input_tokens": 0,
            "output_tokens": 0,
            "cached_tokens": 0,
            "total_tokens": 0,
            "min_response_time": float('inf'),
            "max_response_time": 0.0,
            "cache_hits": 0,
        }
