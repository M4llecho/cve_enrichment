"""
CWE (Common Weakness Enumeration) downloader.
"""

import logging
import zipfile
import io
from pathlib import Path
from typing import Optional

from config import DATA_SOURCES
from .base import BaseDownloader

logger = logging.getLogger(__name__)


class CWEDownloader(BaseDownloader):
    """Downloader for CWE data from MITRE."""

    def __init__(self):
        super().__init__("CWE")
        self.config = DATA_SOURCES["cwe"]

    def download(self, force: bool = False) -> Path:
        """
        Download and extract CWE XML file.

        Returns the path to the extracted XML file.
        """
        cache_file = self.config["cache_file"]
        extracted_file = self.config["extracted_file"]

        # Check cache
        if not force and self._is_cache_valid(extracted_file):
            logger.info("Using cached CWE data")
            return extracted_file

        logger.info("Downloading CWE data from MITRE...")

        try:
            response = self._download_with_retry(
                self.config["url"],
                timeout=120
            )

            # Save the zip file
            self._save_to_cache(cache_file, response.content)

            # Extract the XML
            logger.info("Extracting CWE XML...")
            with zipfile.ZipFile(io.BytesIO(response.content)) as zf:
                # Find the XML file in the archive
                xml_files = [n for n in zf.namelist() if n.endswith(".xml")]
                if not xml_files:
                    raise ValueError("No XML file found in CWE archive")

                # Extract the first XML file
                xml_content = zf.read(xml_files[0])
                extracted_file.parent.mkdir(parents=True, exist_ok=True)
                with open(extracted_file, "wb") as f:
                    f.write(xml_content)

            logger.info(f"CWE data extracted to {extracted_file}")
            return extracted_file

        except Exception as e:
            logger.error(f"Error downloading CWE data: {e}")
            raise

    def get_xml_path(self) -> Optional[Path]:
        """Get the path to the CWE XML file if it exists."""
        extracted_file = self.config["extracted_file"]
        if extracted_file.exists():
            return extracted_file
        return None
