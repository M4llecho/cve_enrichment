"""
Rate Limiter for Gemini API.

Handles RPM (requests per minute), TPM (tokens per minute), and RPD (requests per day) limits.
"""

import asyncio
import logging
import time
from collections import deque
from dataclasses import dataclass, field
from typing import Deque

logger = logging.getLogger(__name__)


@dataclass
class GeminiRateLimiter:
    """
    Rate limiter for Gemini API with support for:
    - RPM: Requests Per Minute (default: 1000)
    - TPM: Tokens Per Minute (default: 4,000,000)
    - RPD: Requests Per Day (default: 10,000)
    """

    rpm_limit: int = 1000
    tpm_limit: int = 4_000_000
    rpd_limit: int = 10_000

    # Internal tracking (use default_factory for mutable defaults)
    _request_times: Deque[float] = field(default_factory=deque)
    _token_counts: Deque[int] = field(default_factory=deque)
    _daily_requests: int = 0
    _day_start: float = field(default_factory=time.time)
    _lock: asyncio.Lock = field(default_factory=asyncio.Lock)

    async def acquire(self, estimated_tokens: int = 2000) -> None:
        """
        Acquire permission to make a request.
        Waits if rate limits would be exceeded.

        Args:
            estimated_tokens: Estimated total tokens for this request (input + output)
        """
        async with self._lock:
            now = time.time()

            # Reset daily counter if new day
            if now - self._day_start > 86400:
                logger.info("Daily rate limit reset")
                self._daily_requests = 0
                self._day_start = now

            # Check daily limit
            if self._daily_requests >= self.rpd_limit:
                raise RuntimeError(
                    f"Daily request limit ({self.rpd_limit}) reached. "
                    f"Try again after {86400 - (now - self._day_start):.0f} seconds."
                )

            # Clean up old entries (older than 60 seconds)
            self._cleanup_old_entries(now)

            # Wait for RPM limit
            await self._wait_for_rpm(now)

            # Wait for TPM limit
            await self._wait_for_tpm(now, estimated_tokens)

            # Record this request
            self._request_times.append(time.time())
            self._token_counts.append(estimated_tokens)
            self._daily_requests += 1

    def _cleanup_old_entries(self, now: float) -> None:
        """Remove entries older than 60 seconds."""
        while self._request_times and now - self._request_times[0] > 60:
            self._request_times.popleft()
            self._token_counts.popleft()

    async def _wait_for_rpm(self, now: float) -> None:
        """Wait if RPM limit would be exceeded."""
        while len(self._request_times) >= self.rpm_limit:
            oldest = self._request_times[0]
            sleep_time = 60 - (now - oldest) + 0.1  # Small buffer
            if sleep_time > 0:
                logger.debug(f"RPM limit reached, waiting {sleep_time:.1f}s")
                await asyncio.sleep(sleep_time)
            now = time.time()
            self._cleanup_old_entries(now)

    async def _wait_for_tpm(self, now: float, estimated_tokens: int) -> None:
        """Wait if TPM limit would be exceeded."""
        current_tpm = sum(self._token_counts)
        while current_tpm + estimated_tokens > self.tpm_limit:
            if not self._request_times:
                break
            oldest = self._request_times[0]
            sleep_time = 60 - (now - oldest) + 0.1
            if sleep_time > 0:
                logger.debug(f"TPM limit reached ({current_tpm:,} tokens), waiting {sleep_time:.1f}s")
                await asyncio.sleep(sleep_time)
            now = time.time()
            self._cleanup_old_entries(now)
            current_tpm = sum(self._token_counts)

    def update_tokens(self, actual_tokens: int) -> None:
        """
        Update the last request with actual token count.
        Call this after receiving the API response.

        Args:
            actual_tokens: Actual total tokens used (from API response)
        """
        if self._token_counts:
            self._token_counts[-1] = actual_tokens

    def get_stats(self) -> dict:
        """Get current rate limiter statistics."""
        now = time.time()
        self._cleanup_old_entries(now)

        return {
            "requests_last_minute": len(self._request_times),
            "tokens_last_minute": sum(self._token_counts),
            "requests_today": self._daily_requests,
            "rpm_remaining": self.rpm_limit - len(self._request_times),
            "tpm_remaining": self.tpm_limit - sum(self._token_counts),
            "rpd_remaining": self.rpd_limit - self._daily_requests,
        }


# Singleton instance for shared rate limiting
_default_limiter: GeminiRateLimiter = None


def get_rate_limiter(
    rpm_limit: int = 1000,
    tpm_limit: int = 4_000_000,
    rpd_limit: int = 10_000,
) -> GeminiRateLimiter:
    """
    Get the singleton rate limiter instance.

    Args:
        rpm_limit: Requests per minute limit
        tpm_limit: Tokens per minute limit
        rpd_limit: Requests per day limit

    Returns:
        Shared GeminiRateLimiter instance
    """
    global _default_limiter
    if _default_limiter is None:
        _default_limiter = GeminiRateLimiter(
            rpm_limit=rpm_limit,
            tpm_limit=tpm_limit,
            rpd_limit=rpd_limit,
        )
    return _default_limiter


def reset_rate_limiter() -> None:
    """Reset the singleton rate limiter (useful for testing)."""
    global _default_limiter
    _default_limiter = None
