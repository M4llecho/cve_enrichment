"""
NVD JSON 2.0 Feeds downloader for bulk CVE download.
Downloads yearly feed files which are much faster than API calls.
"""

import gzip
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Generator, List, Optional

from config import CACHE_DIR
from parsers import CPEParser
from .base import BaseDownloader

logger = logging.getLogger(__name__)


def parse_cve_from_feed(cve: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """
    Parse NVD CVE data from feed format into our internal format.

    This is a standalone function to allow reuse across modules.
    The feed format is the same as the API response format.
    """
    if not cve:
        return None

    cve_id = cve.get("id")
    if not cve_id:
        return None

    # Get description (prefer English)
    descriptions = cve.get("descriptions", [])
    description = None
    for desc in descriptions:
        if desc.get("lang") == "en":
            description = desc.get("value")
            break
    if not description and descriptions:
        description = descriptions[0].get("value")

    # Get dates
    published = cve.get("published")
    last_modified = cve.get("lastModified")

    # Parse dates
    published_date = None
    last_modified_date = None
    if published:
        try:
            published_date = datetime.fromisoformat(
                published.replace("Z", "+00:00")
            )
        except ValueError:
            pass
    if last_modified:
        try:
            last_modified_date = datetime.fromisoformat(
                last_modified.replace("Z", "+00:00")
            )
        except ValueError:
            pass

    # Get CVSS metrics (priority: 4.0 -> 3.1 -> 3.0 -> 2.0)
    cvss_score = None
    cvss_vector = None
    cvss_severity = None
    cvss_version = None

    metrics = cve.get("metrics", {})

    # Try CVSS 4.0 first
    if "cvssMetricV40" in metrics and metrics["cvssMetricV40"]:
        cvss_data = metrics["cvssMetricV40"][0].get("cvssData", {})
        cvss_score = cvss_data.get("baseScore")
        cvss_vector = cvss_data.get("vectorString")
        cvss_severity = cvss_data.get("baseSeverity")
        cvss_version = "4.0"
    # Then CVSS 3.1
    elif "cvssMetricV31" in metrics and metrics["cvssMetricV31"]:
        cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
        cvss_score = cvss_data.get("baseScore")
        cvss_vector = cvss_data.get("vectorString")
        cvss_severity = cvss_data.get("baseSeverity")
        cvss_version = "3.1"
    # Then CVSS 3.0
    elif "cvssMetricV30" in metrics and metrics["cvssMetricV30"]:
        cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
        cvss_score = cvss_data.get("baseScore")
        cvss_vector = cvss_data.get("vectorString")
        cvss_severity = cvss_data.get("baseSeverity")
        cvss_version = "3.0"
    # Finally CVSS 2.0 as fallback
    elif "cvssMetricV2" in metrics and metrics["cvssMetricV2"]:
        cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
        cvss_score = cvss_data.get("baseScore")
        cvss_vector = cvss_data.get("vectorString")
        # CVSS 2.0 doesn't have baseSeverity, calculate from score
        if cvss_score is not None:
            if cvss_score >= 7.0:
                cvss_severity = "HIGH"
            elif cvss_score >= 4.0:
                cvss_severity = "MEDIUM"
            else:
                cvss_severity = "LOW"
        cvss_version = "2.0"

    # Get all CWEs (a CVE can have multiple CWEs)
    cwe_ids = []
    weaknesses = cve.get("weaknesses", [])
    for weakness in weaknesses:
        descs = weakness.get("description", [])
        for desc in descs:
            value = desc.get("value", "")
            if value.startswith("CWE-") and value not in cwe_ids:
                cwe_ids.append(value)

    # Get references with Exploit and Patch tags
    references = cve.get("references", [])
    exploit_count = 0
    has_patch = False

    for ref in references:
        tags = ref.get("tags", [])
        if "Exploit" in tags:
            exploit_count += 1
        if "Patch" in tags:
            has_patch = True

    # Get vulnerability status (e.g., Analyzed, Modified, Rejected, Awaiting Analysis)
    vuln_status = cve.get("vulnStatus")

    # Get CPE (affected products/platforms) and extract vendor/product
    cpe_list = []
    configurations = cve.get("configurations", [])
    for config in configurations:
        nodes = config.get("nodes", [])
        for node in nodes:
            cpe_matches = node.get("cpeMatch", [])
            for cpe_match in cpe_matches:
                cpe_uri = cpe_match.get("criteria")
                if cpe_uri and cpe_uri not in cpe_list:
                    cpe_list.append(cpe_uri)

    # Extract affected vendors/products from CPE
    affected = CPEParser.extract_affected_products(cpe_list)

    return {
        "cve_id": cve_id,
        "description": description,
        "published_date": published_date,
        "last_modified": last_modified_date,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "cvss_severity": cvss_severity,
        "cvss_version": cvss_version,
        "vuln_status": vuln_status,
        "cwe_ids": cwe_ids,
        "has_exploit": exploit_count > 0,
        "exploit_count": exploit_count,
        "has_patch": has_patch,
        "reference_count": len(references),
        "affected_vendors": affected["vendors"],
        "affected_products": affected["products"],
        "affected_products_detail": affected["details"],
    }

# NVD Feeds base URL
NVD_FEEDS_BASE_URL = "https://nvd.nist.gov/feeds/json/cve/2.0"

# Available feed types
FEED_TYPES = {
    "modified": "nvdcve-2.0-modified.json.gz",  # Recently modified (last 8 days)
    "recent": "nvdcve-2.0-recent.json.gz",      # Recently added (last 8 days)
}

# Year range for yearly feeds (NVD data starts from 2002)
START_YEAR = 2002


class NVDFeedsDownloader(BaseDownloader):
    """Downloader for NVD JSON 2.0 Feeds (bulk download)."""

    def __init__(self):
        super().__init__("NVD-Feeds")
        self.feeds_dir = CACHE_DIR / "nvd_feeds"
        self.feeds_dir.mkdir(exist_ok=True)

    def get_available_years(self) -> List[int]:
        """Get list of years for which feeds are available."""
        current_year = datetime.now().year
        return list(range(START_YEAR, current_year + 1))

    def _get_feed_url(self, year: int) -> str:
        """Get URL for a yearly feed."""
        return f"{NVD_FEEDS_BASE_URL}/nvdcve-2.0-{year}.json.gz"

    def _get_feed_path(self, year: int) -> Path:
        """Get local path for a yearly feed."""
        return self.feeds_dir / f"nvdcve-2.0-{year}.json.gz"

    def _get_json_path(self, year: int) -> Path:
        """Get local path for extracted JSON."""
        return self.feeds_dir / f"nvdcve-2.0-{year}.json"

    def download_year(self, year: int, force: bool = False) -> Optional[Path]:
        """
        Download feed for a specific year.

        Returns path to the downloaded .gz file.
        """
        feed_path = self._get_feed_path(year)

        # Check cache (feeds are updated daily, so 12h cache is reasonable)
        if not force and feed_path.exists():
            # Check if file is less than 12 hours old
            from datetime import timedelta
            modified_time = datetime.fromtimestamp(feed_path.stat().st_mtime)
            if datetime.now() - modified_time < timedelta(hours=12):
                logger.debug(f"Using cached feed for {year}")
                return feed_path

        url = self._get_feed_url(year)
        logger.info(f"Downloading NVD feed for {year}...")

        try:
            response = self._download_with_retry(url, timeout=300)
            self._save_to_cache(feed_path, response.content)
            logger.info(f"Downloaded feed for {year} ({len(response.content) / 1024 / 1024:.1f} MB)")
            return feed_path
        except Exception as e:
            logger.error(f"Failed to download feed for {year}: {e}")
            return None

    def download_all_years(self, force: bool = False) -> List[Path]:
        """Download feeds for all available years."""
        years = self.get_available_years()
        downloaded = []

        for year in years:
            path = self.download_year(year, force=force)
            if path:
                downloaded.append(path)

        logger.info(f"Downloaded {len(downloaded)}/{len(years)} yearly feeds")
        return downloaded

    def parse_feed_raw(self, feed_path: Path) -> Generator[Dict[str, Any], None, None]:
        """
        Parse a feed file and yield raw CVE items (unparsed).

        Handles both .gz and .json files.
        """
        logger.info(f"Parsing feed: {feed_path.name}")

        try:
            if feed_path.suffix == ".gz":
                with gzip.open(feed_path, "rt", encoding="utf-8") as f:
                    data = json.load(f)
            else:
                with open(feed_path, "r", encoding="utf-8") as f:
                    data = json.load(f)

            vulnerabilities = data.get("vulnerabilities", [])
            logger.info(f"Found {len(vulnerabilities)} CVEs in {feed_path.name}")

            for vuln in vulnerabilities:
                cve = vuln.get("cve", {})
                if cve:
                    yield cve

        except (json.JSONDecodeError, gzip.BadGzipFile, IOError) as e:
            logger.error(f"Error parsing feed {feed_path}: {e}")

    def parse_feed(self, feed_path: Path) -> Generator[Dict[str, Any], None, None]:
        """
        Parse a feed file and yield parsed CVE items in our internal format.

        Handles both .gz and .json files.
        """
        for raw_cve in self.parse_feed_raw(feed_path):
            parsed = parse_cve_from_feed(raw_cve)
            if parsed:
                yield parsed

    def parse_all_feeds(self, force_download: bool = False) -> Generator[Dict[str, Any], None, None]:
        """
        Download and parse all yearly feeds.

        Yields CVE items from all years.
        """
        # Download all feeds first
        feed_paths = self.download_all_years(force=force_download)

        # Parse each feed
        for feed_path in feed_paths:
            yield from self.parse_feed(feed_path)

    def get_feed_stats(self) -> Dict[str, Any]:
        """Get statistics about cached feeds."""
        stats = {
            "cached_feeds": [],
            "total_size_mb": 0,
        }

        for year in self.get_available_years():
            feed_path = self._get_feed_path(year)
            if feed_path.exists():
                size_mb = feed_path.stat().st_size / 1024 / 1024
                modified = datetime.fromtimestamp(feed_path.stat().st_mtime)
                stats["cached_feeds"].append({
                    "year": year,
                    "size_mb": round(size_mb, 2),
                    "modified": modified.isoformat(),
                })
                stats["total_size_mb"] += size_mb

        stats["total_size_mb"] = round(stats["total_size_mb"], 2)
        return stats
