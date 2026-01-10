"""
MITRE ATT&CK Enterprise downloader.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, Optional

from config import DATA_SOURCES
from .base import BaseDownloader

logger = logging.getLogger(__name__)


class ATTACKDownloader(BaseDownloader):
    """Downloader for MITRE ATT&CK Enterprise data."""

    def __init__(self):
        super().__init__("ATT&CK")
        self.config = DATA_SOURCES["attack"]

    def download(self, force: bool = False) -> Path:
        """
        Download ATT&CK Enterprise JSON file.

        Returns the path to the JSON file.
        """
        cache_file = self.config["cache_file"]

        # Check cache
        if not force and self._is_cache_valid(cache_file):
            logger.info("Using cached ATT&CK data")
            return cache_file

        logger.info("Downloading ATT&CK Enterprise data...")

        try:
            response = self._download_with_retry(
                self.config["url"],
                timeout=120
            )

            # Validate JSON
            try:
                json.loads(response.content)
            except json.JSONDecodeError as e:
                raise ValueError(f"Invalid JSON in ATT&CK response: {e}")

            # Save the JSON file
            self._save_to_cache(cache_file, response.content)

            logger.info(f"ATT&CK data saved to {cache_file}")
            return cache_file

        except Exception as e:
            logger.error(f"Error downloading ATT&CK data: {e}")
            raise

    def get_json_path(self) -> Optional[Path]:
        """Get the path to the ATT&CK JSON file if it exists."""
        cache_file = self.config["cache_file"]
        if cache_file.exists():
            return cache_file
        return None

    def load_data(self) -> Optional[Dict[str, Any]]:
        """Load ATT&CK data from cache."""
        json_path = self.get_json_path()
        if not json_path:
            return None

        try:
            with open(json_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading ATT&CK data: {e}")
            return None
