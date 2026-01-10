"""
CAPEC (Common Attack Pattern Enumeration and Classification) downloader.
"""

import logging
from pathlib import Path
from typing import Optional

from config import DATA_SOURCES
from .base import BaseDownloader

logger = logging.getLogger(__name__)


class CAPECDownloader(BaseDownloader):
    """Downloader for CAPEC data from MITRE."""

    def __init__(self):
        super().__init__("CAPEC")
        self.config = DATA_SOURCES["capec"]

    def download(self, force: bool = False) -> Path:
        """
        Download CAPEC XML file.

        Returns the path to the XML file.
        """
        cache_file = self.config["cache_file"]

        # Check cache
        if not force and self._is_cache_valid(cache_file):
            logger.info("Using cached CAPEC data")
            return cache_file

        logger.info("Downloading CAPEC data from MITRE...")

        try:
            response = self._download_with_retry(
                self.config["url"],
                timeout=120
            )

            # Save the XML file
            self._save_to_cache(cache_file, response.content)

            logger.info(f"CAPEC data saved to {cache_file}")
            return cache_file

        except Exception as e:
            logger.error(f"Error downloading CAPEC data: {e}")
            raise

    def get_xml_path(self) -> Optional[Path]:
        """Get the path to the CAPEC XML file if it exists."""
        cache_file = self.config["cache_file"]
        if cache_file.exists():
            return cache_file
        return None
