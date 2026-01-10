"""
CISA KEV (Known Exploited Vulnerabilities) downloader.
"""

import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from config import DATA_SOURCES
from .base import BaseDownloader

logger = logging.getLogger(__name__)


class KEVDownloader(BaseDownloader):
    """Downloader for CISA Known Exploited Vulnerabilities catalog."""

    def __init__(self):
        super().__init__("KEV")
        self.config = DATA_SOURCES["kev"]
        self._kev_cache: Optional[Dict[str, Dict[str, Any]]] = None
        self._kev_set: Optional[Set[str]] = None

    def download(self, force: bool = False) -> Path:
        """
        Download CISA KEV catalog.

        Returns the path to the cached JSON file.
        """
        cache_file = self.config["cache_file"]

        # Check cache
        if not force and self._is_cache_valid(cache_file):
            logger.info("Using cached KEV data")
            return cache_file

        logger.info("Downloading CISA KEV catalog...")

        try:
            response = self._download_with_retry(
                self.config["url"],
                timeout=60
            )

            data = response.json()

            # Save the JSON file
            self._save_to_cache(cache_file, response.content)

            vuln_count = len(data.get("vulnerabilities", []))
            logger.info(f"KEV data saved. Total vulnerabilities: {vuln_count}")
            return cache_file

        except Exception as e:
            logger.error(f"Error downloading KEV data: {e}")
            raise

    def load_kev(self, force_reload: bool = False) -> Dict[str, Dict[str, Any]]:
        """
        Load KEV data into memory as a dict keyed by CVE ID.

        Returns: {cve_id: {date_added, due_date, ransomware_use, ...}}
        """
        if self._kev_cache is not None and not force_reload:
            return self._kev_cache

        cache_file = self.config["cache_file"]
        if not cache_file.exists():
            logger.warning("KEV cache file not found. Run download first.")
            return {}

        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            kev = {}
            for vuln in data.get("vulnerabilities", []):
                cve_id = vuln.get("cveID")
                if cve_id:
                    # Parse dates
                    date_added = vuln.get("dateAdded")
                    due_date = vuln.get("dueDate")

                    kev[cve_id] = {
                        "date_added": self._parse_date(date_added),
                        "due_date": self._parse_date(due_date),
                        "ransomware_use": vuln.get("knownRansomwareCampaignUse", "Unknown") == "Known",
                        "vendor": vuln.get("vendorProject"),
                        "product": vuln.get("product"),
                        "vulnerability_name": vuln.get("vulnerabilityName"),
                        "short_description": vuln.get("shortDescription"),
                        "required_action": vuln.get("requiredAction"),
                        "notes": vuln.get("notes"),
                    }

            self._kev_cache = kev
            self._kev_set = set(kev.keys())
            logger.info(f"Loaded {len(kev)} KEV entries into memory")
            return kev

        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading KEV data: {e}")
            return {}

    def _parse_date(self, date_str: Optional[str]) -> Optional[datetime]:
        """Parse date string to datetime."""
        if not date_str:
            return None
        try:
            return datetime.strptime(date_str, "%Y-%m-%d")
        except ValueError:
            return None

    def get_kev_ids(self) -> Set[str]:
        """Get set of all CVE IDs in KEV."""
        if self._kev_set is not None:
            return self._kev_set

        self.load_kev()
        return self._kev_set or set()

    def is_in_kev(self, cve_id: str) -> bool:
        """Check if a CVE is in the KEV catalog."""
        return cve_id in self.get_kev_ids()

    def get_kev_details(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get KEV details for a CVE."""
        kev = self.load_kev()
        return kev.get(cve_id)

    def get_kev_details_batch(
        self, cve_ids: List[str]
    ) -> Dict[str, Dict[str, Any]]:
        """Get KEV details for multiple CVEs."""
        kev = self.load_kev()
        return {cve_id: kev[cve_id] for cve_id in cve_ids if cve_id in kev}
