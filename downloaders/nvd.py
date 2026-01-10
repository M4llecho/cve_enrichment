"""
NVD (National Vulnerability Database) API downloader.
"""

import logging
import time
from datetime import datetime
from typing import Any, Dict, Generator, List, Optional

from config import NVD_API_KEY, NVD_BASE_URL, NVD_RATE_LIMIT, NVD_RATE_WINDOW
from .base import BaseDownloader

logger = logging.getLogger(__name__)


class NVDDownloader(BaseDownloader):
    """Downloader for NVD CVE data via API."""

    def __init__(self):
        super().__init__("NVD")
        self.api_key = NVD_API_KEY
        self.base_url = NVD_BASE_URL
        self.rate_limit = NVD_RATE_LIMIT
        self.rate_window = NVD_RATE_WINDOW
        self.request_count = 0
        self.window_start = time.time()

        if self.api_key:
            self.session.headers.update({"apiKey": self.api_key})
            logger.info("NVD API key configured - using higher rate limit")
        else:
            logger.warning(
                "No NVD API key configured - using lower rate limit "
                f"({self.rate_limit} requests per {self.rate_window}s)"
            )

    def _respect_rate_limit(self) -> None:
        """Ensure we don't exceed the rate limit."""
        self.request_count += 1

        # Check if we need to wait
        if self.request_count >= self.rate_limit:
            elapsed = time.time() - self.window_start
            if elapsed < self.rate_window:
                wait_time = self.rate_window - elapsed + 1
                logger.info(f"Rate limit reached. Waiting {wait_time:.1f}s...")
                time.sleep(wait_time)

            # Reset window
            self.window_start = time.time()
            self.request_count = 0

    def get_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get a single CVE by ID."""
        self._respect_rate_limit()

        try:
            response = self._download_with_retry(
                self.base_url,
                params={"cveId": cve_id}
            )
            data = response.json()

            if data.get("totalResults", 0) > 0:
                vulnerabilities = data.get("vulnerabilities", [])
                if vulnerabilities:
                    return self._parse_cve(vulnerabilities[0].get("cve", {}))

            logger.warning(f"CVE {cve_id} not found in NVD")
            return None

        except Exception as e:
            logger.error(f"Error fetching CVE {cve_id}: {e}")
            return None

    def get_cves_batch(
        self,
        cve_ids: List[str],
        progress_callback: Optional[callable] = None
    ) -> List[Dict[str, Any]]:
        """Get multiple CVEs by ID."""
        results = []

        for i, cve_id in enumerate(cve_ids):
            cve_data = self.get_cve(cve_id)
            if cve_data:
                results.append(cve_data)

            if progress_callback:
                progress_callback(i + 1, len(cve_ids))

        return results

    def get_all_cves(
        self,
        start_index: int = 0,
        results_per_page: int = 2000,
        pub_start_date: Optional[datetime] = None,
        pub_end_date: Optional[datetime] = None,
        last_mod_start_date: Optional[datetime] = None,
        last_mod_end_date: Optional[datetime] = None,
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Generator that yields all CVEs from NVD.
        Uses pagination to handle large result sets.

        Args:
            start_index: Starting index for pagination
            results_per_page: Number of results per page (max 2000)
            pub_start_date: Filter by publication start date
            pub_end_date: Filter by publication end date
            last_mod_start_date: Filter by last modified start date
            last_mod_end_date: Filter by last modified end date
        """
        params = {
            "resultsPerPage": results_per_page,
            "startIndex": start_index,
        }

        if pub_start_date:
            params["pubStartDate"] = pub_start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        if pub_end_date:
            params["pubEndDate"] = pub_end_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        if last_mod_start_date:
            params["lastModStartDate"] = last_mod_start_date.strftime("%Y-%m-%dT%H:%M:%S.000")
        if last_mod_end_date:
            params["lastModEndDate"] = last_mod_end_date.strftime("%Y-%m-%dT%H:%M:%S.000")

        total_results = None
        current_index = start_index

        while True:
            self._respect_rate_limit()
            params["startIndex"] = current_index

            try:
                response = self._download_with_retry(self.base_url, params=params)
                data = response.json()

                if total_results is None:
                    total_results = data.get("totalResults", 0)
                    logger.info(f"Total CVEs to fetch: {total_results}")

                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    break

                for vuln in vulnerabilities:
                    cve = vuln.get("cve", {})
                    parsed = self._parse_cve(cve)
                    if parsed:
                        yield parsed

                current_index += len(vulnerabilities)
                logger.info(f"Fetched {current_index}/{total_results} CVEs")

                if current_index >= total_results:
                    break

            except Exception as e:
                logger.error(f"Error fetching CVEs at index {current_index}: {e}")
                raise

    def _parse_cve(self, cve: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Parse NVD CVE data into our format."""
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
            descriptions = weakness.get("description", [])
            for desc in descriptions:
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

        # Get CPE (affected products/platforms)
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
            "cpe": cpe_list,
        }

    def get_modified_cves(
        self,
        since: datetime,
        until: Optional[datetime] = None,
        results_per_page: int = 2000,
    ) -> Generator[Dict[str, Any], None, None]:
        """
        Get CVEs modified since a specific date.

        Args:
            since: Start date for modification filter
            until: End date for modification filter (defaults to now)
            results_per_page: Number of results per page

        Yields:
            Parsed CVE data
        """
        if until is None:
            until = datetime.now()

        logger.info(f"Fetching CVEs modified since {since.isoformat()}")
        yield from self.get_all_cves(
            last_mod_start_date=since,
            last_mod_end_date=until,
            results_per_page=results_per_page,
        )

    def download(self, force: bool = False) -> Generator[Dict[str, Any], None, None]:
        """Download all CVEs from NVD."""
        return self.get_all_cves()
