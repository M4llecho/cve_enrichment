"""
Nuclei templates downloader from ProjectDiscovery.
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


class NucleiDownloader(BaseDownloader):
    """Downloader for ProjectDiscovery Nuclei templates repository."""

    def __init__(self):
        super().__init__("Nuclei")
        self.config = DATA_SOURCES["nuclei"]

    def download(self, force: bool = False) -> Path:
        """
        Download and extract Nuclei templates repository.

        Returns the path to the extracted directory.
        """
        cache_file = self.config["cache_file"]
        extracted_dir = self.config["extracted_dir"]

        # Check cache (use the extracted directory for cache validation)
        if not force and self._is_cache_valid(cache_file):
            if extracted_dir.exists():
                logger.info("Using cached Nuclei templates")
                return extracted_dir

        logger.info("Downloading Nuclei templates from GitHub...")

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
            logger.info("Extracting Nuclei templates...")
            with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
                # Extract to cache directory
                extract_base = cache_file.parent
                zf.extractall(extract_base)

                # The ZIP extracts to nuclei-templates-main/ folder
                # Rename to our expected directory name if different
                extracted_name = zf.namelist()[0].split('/')[0]
                actual_extracted = extract_base / extracted_name

                if actual_extracted != extracted_dir and actual_extracted.exists():
                    if extracted_dir.exists():
                        shutil.rmtree(extracted_dir)
                    actual_extracted.rename(extracted_dir)

            logger.info(f"Nuclei templates extracted to {extracted_dir}")
            return extracted_dir

        except Exception as e:
            logger.error(f"Error downloading Nuclei templates: {e}")
            raise

    def get_templates_dir(self) -> Optional[Path]:
        """
        Get the path to the Nuclei templates base directory.

        Returns the path to the extracted Nuclei repository if it exists.
        """
        extracted_dir = self.config["extracted_dir"]

        if extracted_dir.exists():
            return extracted_dir
        return None

    def get_cves_dir(self) -> Optional[Path]:
        """
        Get the path to the CVE templates directory (http/cves/).

        Returns the path to the CVE templates if it exists.
        """
        templates_dir = self.get_templates_dir()
        if templates_dir:
            cves_dir = templates_dir / "http" / "cves"
            if cves_dir.exists():
                return cves_dir
        return None
