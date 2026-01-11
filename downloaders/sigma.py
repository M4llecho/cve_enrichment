"""
SigmaHQ detection rules downloader.
"""

import logging
import shutil
import zipfile
import io
from pathlib import Path
from typing import Optional

from config import DATA_SOURCES
from .base import BaseDownloader

logger = logging.getLogger(__name__)


class SigmaDownloader(BaseDownloader):
    """Downloader for SigmaHQ detection rules repository."""

    def __init__(self):
        super().__init__("Sigma")
        self.config = DATA_SOURCES["sigma"]

    def download(self, force: bool = False) -> Path:
        """
        Download and extract SigmaHQ rules repository.

        Returns the path to the extracted directory.
        """
        cache_file = self.config["cache_file"]
        extracted_dir = self.config["extracted_dir"]

        # Check cache (use the extracted directory for cache validation)
        if not force and self._is_cache_valid(cache_file):
            if extracted_dir.exists():
                logger.info("Using cached Sigma rules")
                return extracted_dir

        logger.info("Downloading SigmaHQ rules from GitHub...")

        try:
            response = self._download_with_retry(
                self.config["url"],
                timeout=300  # 5 minutes for large repo
            )

            # Save the zip file
            self._save_to_cache(cache_file, response.content)

            # Remove old extracted directory if exists
            if extracted_dir.exists():
                shutil.rmtree(extracted_dir)

            # Extract the ZIP
            logger.info("Extracting Sigma rules...")
            with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
                # Extract to cache directory
                extract_base = cache_file.parent
                zf.extractall(extract_base)

                # The ZIP extracts to sigma-master/ folder
                # Rename to our expected directory name if different
                extracted_name = zf.namelist()[0].split('/')[0]
                actual_extracted = extract_base / extracted_name

                if actual_extracted != extracted_dir and actual_extracted.exists():
                    if extracted_dir.exists():
                        shutil.rmtree(extracted_dir)
                    actual_extracted.rename(extracted_dir)

            logger.info(f"Sigma rules extracted to {extracted_dir}")
            return extracted_dir

        except Exception as e:
            logger.error(f"Error downloading Sigma rules: {e}")
            raise

    def get_rules_dir(self) -> Optional[Path]:
        """
        Get the path to the Sigma base directory (contains rules/, rules-emerging-threats/, etc.).

        Returns the path to the extracted Sigma repository if it exists.
        """
        extracted_dir = self.config["extracted_dir"]

        if extracted_dir.exists():
            return extracted_dir
        return None

    def get_extracted_dir(self) -> Optional[Path]:
        """Get the path to the extracted Sigma directory if it exists."""
        return self.get_rules_dir()
