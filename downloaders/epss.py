"""
EPSS (Exploit Prediction Scoring System) downloader.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Optional

from config import DATA_SOURCES
from .base import BaseDownloader

logger = logging.getLogger(__name__)


class EPSSDownloader(BaseDownloader):
    """Downloader for EPSS scores from FIRST."""

    def __init__(self):
        super().__init__("EPSS")
        self.config = DATA_SOURCES["epss"]
        self._scores_cache: Optional[Dict[str, Dict[str, float]]] = None

    def download(self, force: bool = False) -> Path:
        """
        Download EPSS scores.

        Returns the path to the cached JSON file.
        """
        cache_file = self.config["cache_file"]

        # Check cache
        if not force and self._is_cache_valid(cache_file):
            logger.info("Using cached EPSS data")
            return cache_file

        logger.info("Downloading EPSS scores from FIRST...")

        try:
            # First request to get total count
            response = self._download_with_retry(
                self.config["url"],
                params={"limit": 1},
                timeout=60
            )
            first_data = response.json()
            total = first_data.get("total", 0)
            logger.info(f"Total EPSS scores available: {total}")

            # Download all scores with pagination (API max is 10000 per request)
            all_scores = []
            limit = 10000
            offset = 0

            while offset < total:
                logger.info(f"Downloading EPSS scores {offset} to {offset + limit}...")
                response = self._download_with_retry(
                    self.config["url"],
                    params={"limit": limit, "offset": offset},
                    timeout=120
                )

                data = response.json()
                batch = data.get("data", [])
                if not batch:
                    break

                all_scores.extend(batch)
                offset += len(batch)

            # Build final JSON structure
            final_data = {
                "status": "OK",
                "total": len(all_scores),
                "data": all_scores
            }

            # Save the JSON file
            import json
            content = json.dumps(final_data).encode('utf-8')
            self._save_to_cache(cache_file, content)

            logger.info(f"EPSS data saved. Downloaded {len(all_scores)} scores")
            return cache_file

        except Exception as e:
            logger.error(f"Error downloading EPSS data: {e}")
            raise

    def load_scores(self, force_reload: bool = False) -> Dict[str, Dict[str, float]]:
        """
        Load EPSS scores into memory as a dict keyed by CVE ID.

        Returns: {cve_id: {"epss": score, "percentile": percentile}}
        """
        if self._scores_cache is not None and not force_reload:
            return self._scores_cache

        cache_file = self.config["cache_file"]
        if not cache_file.exists():
            logger.warning("EPSS cache file not found. Run download first.")
            return {}

        try:
            with open(cache_file, "r", encoding="utf-8") as f:
                data = json.load(f)

            scores = {}
            for item in data.get("data", []):
                cve_id = item.get("cve")
                if cve_id:
                    scores[cve_id] = {
                        "epss": float(item.get("epss", 0)),
                        "percentile": float(item.get("percentile", 0)),
                    }

            self._scores_cache = scores
            logger.info(f"Loaded {len(scores)} EPSS scores into memory")
            return scores

        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading EPSS data: {e}")
            return {}

    def get_score(self, cve_id: str) -> Optional[Dict[str, float]]:
        """Get EPSS score for a single CVE."""
        scores = self.load_scores()
        return scores.get(cve_id)

    def get_scores_batch(
        self, cve_ids: List[str]
    ) -> Dict[str, Dict[str, float]]:
        """Get EPSS scores for multiple CVEs."""
        scores = self.load_scores()
        return {cve_id: scores[cve_id] for cve_id in cve_ids if cve_id in scores}

    def get_score_api(self, cve_id: str) -> Optional[Dict[str, float]]:
        """
        Get EPSS score for a single CVE directly from API.
        Use this for real-time queries when cache might be stale.
        """
        try:
            response = self._download_with_retry(
                f"{self.config['url']}?cve={cve_id}",
                timeout=30
            )
            data = response.json()

            if data.get("data"):
                item = data["data"][0]
                return {
                    "epss": float(item.get("epss", 0)),
                    "percentile": float(item.get("percentile", 0)),
                }
            return None

        except Exception as e:
            logger.error(f"Error fetching EPSS for {cve_id}: {e}")
            return None
