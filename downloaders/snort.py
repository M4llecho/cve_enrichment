"""
Emerging Threats Open rules downloader for Snort/Suricata IDS.
"""

import logging
import shutil
import tarfile
import io
from pathlib import Path
from typing import Optional

from config import DATA_SOURCES
from .base import BaseDownloader

logger = logging.getLogger(__name__)


class SnortDownloader(BaseDownloader):
    """Downloader for Emerging Threats Open IDS/IPS rules."""

    def __init__(self):
        super().__init__("Snort")
        self.config = DATA_SOURCES["snort"]

    def download(self, force: bool = False) -> Path:
        """
        Download and extract ET Open rules archive.

        Returns the path to the extracted directory.
        """
        cache_file = self.config["cache_file"]
        extracted_dir = self.config["extracted_dir"]

        # Check cache (use the extracted directory for cache validation)
        if not force and self._is_cache_valid(cache_file):
            if extracted_dir.exists():
                logger.info("Using cached ET Open rules")
                return extracted_dir

        logger.info("Downloading ET Open rules from Emerging Threats...")

        try:
            response = self._download_with_retry(
                self.config["url"],
                timeout=300  # 5 minutes for large archive
            )

            # Save the tar.gz file
            self._save_to_cache(cache_file, response.content)

            # Remove old extracted directory if exists
            if extracted_dir.exists():
                shutil.rmtree(extracted_dir)

            # Create extraction directory
            extracted_dir.mkdir(parents=True, exist_ok=True)

            # Extract the tar.gz
            logger.info("Extracting ET Open rules...")
            with tarfile.open(fileobj=io.BytesIO(response.content), mode='r:gz') as tf:
                tf.extractall(extracted_dir)

            logger.info(f"ET Open rules extracted to {extracted_dir}")
            return extracted_dir

        except Exception as e:
            logger.error(f"Error downloading ET Open rules: {e}")
            raise

    def get_rules_dir(self) -> Optional[Path]:
        """
        Get the path to the rules directory.

        Returns the path to the extracted ET Open rules directory if it exists.
        The rules are in the 'rules' subdirectory of the extracted archive.
        """
        extracted_dir = self.config["extracted_dir"]
        rules_dir = extracted_dir / "rules"

        if rules_dir.exists():
            return rules_dir

        # Fallback to extracted_dir if rules subdir doesn't exist
        if extracted_dir.exists():
            return extracted_dir

        return None

    def get_extracted_dir(self) -> Optional[Path]:
        """Get the path to the extracted ET Open directory if it exists."""
        return self.get_rules_dir()
