"""
Base downloader class with common functionality.
"""

import logging
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Any
import requests

from config import (
    MAX_RETRIES, INITIAL_BACKOFF, MAX_BACKOFF, CACHE_EXPIRY_HOURS, SSL_VERIFY
)

logger = logging.getLogger(__name__)


class BaseDownloader:
    """Base class for all downloaders with retry logic and caching."""

    def __init__(self, name: str):
        self.name = name
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "CVE-Enrichment-Tool/1.0"
        })
        # Configure SSL verification
        self.session.verify = SSL_VERIFY
        if SSL_VERIFY is False:
            # Suppress InsecureRequestWarning when SSL verification is disabled
            import urllib3
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
            logger.warning("SSL verification is disabled. This is insecure!")

    def _is_cache_valid(self, cache_path: Path) -> bool:
        """Check if cache file exists and is still valid."""
        if not cache_path.exists():
            return False

        # Check if cache is expired
        modified_time = datetime.fromtimestamp(cache_path.stat().st_mtime)
        expiry_time = modified_time + timedelta(hours=CACHE_EXPIRY_HOURS)

        if datetime.now() > expiry_time:
            logger.info(f"Cache for {self.name} has expired")
            return False

        return True

    def _download_with_retry(
        self,
        url: str,
        params: Optional[dict] = None,
        headers: Optional[dict] = None,
        timeout: int = 60
    ) -> requests.Response:
        """Download with exponential backoff retry logic."""
        last_exception = None
        backoff = INITIAL_BACKOFF

        for attempt in range(1, MAX_RETRIES + 1):
            try:
                logger.debug(f"Attempt {attempt}/{MAX_RETRIES} for {url}")
                response = self.session.get(
                    url,
                    params=params,
                    headers=headers,
                    timeout=timeout
                )

                # Handle rate limiting
                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", backoff))
                    logger.warning(f"Rate limited. Waiting {retry_after} seconds...")
                    time.sleep(retry_after)
                    backoff = min(backoff * 2, MAX_BACKOFF)
                    continue

                response.raise_for_status()
                return response

            except requests.exceptions.RequestException as e:
                last_exception = e
                logger.warning(f"Attempt {attempt} failed: {e}")

                if attempt < MAX_RETRIES:
                    logger.info(f"Waiting {backoff} seconds before retry...")
                    time.sleep(backoff)
                    backoff = min(backoff * 2, MAX_BACKOFF)

        raise last_exception or Exception(f"Failed to download from {url}")

    def _save_to_cache(self, cache_path: Path, content: bytes) -> None:
        """Save content to cache file."""
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        with open(cache_path, "wb") as f:
            f.write(content)
        logger.info(f"Saved to cache: {cache_path}")

    def _load_from_cache(self, cache_path: Path) -> bytes:
        """Load content from cache file."""
        with open(cache_path, "rb") as f:
            return f.read()

    def download(self, force: bool = False) -> Any:
        """Download data. Override in subclasses."""
        raise NotImplementedError("Subclasses must implement download()")
