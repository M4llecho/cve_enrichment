"""
CVE Enrichment Engine - combines data from all sources.
"""

import logging
from datetime import datetime
from typing import Any, Dict, List, Optional
from pathlib import Path

from tqdm import tqdm

from database import DatabaseManager
from downloaders import (
    NVDDownloader,
    NVDFeedsDownloader,
    CWEDownloader,
    CAPECDownloader,
    ATTACKDownloader,
    EPSSDownloader,
    KEVDownloader,
    SigmaDownloader,
    NucleiDownloader,
)
from parsers import CWEParser, CAPECParser, ATTACKParser, SigmaParser, NucleiParser

logger = logging.getLogger(__name__)


class CVEEnricher:
    """
    Main class for CVE enrichment.
    Coordinates downloading, parsing, and database operations.
    """

    def __init__(self):
        self.db = DatabaseManager()
        self.nvd = NVDDownloader()
        self.nvd_feeds = NVDFeedsDownloader()
        self.cwe_downloader = CWEDownloader()
        self.capec_downloader = CAPECDownloader()
        self.attack_downloader = ATTACKDownloader()
        self.epss = EPSSDownloader()
        self.kev = KEVDownloader()
        self.sigma = SigmaDownloader()
        self.nuclei = NucleiDownloader()

        # Parsers (initialized after download)
        self._cwe_parser: Optional[CWEParser] = None
        self._capec_parser: Optional[CAPECParser] = None
        self._attack_parser: Optional[ATTACKParser] = None
        self._sigma_parser: Optional[SigmaParser] = None
        self._nuclei_parser: Optional[NucleiParser] = None

    def download_all_sources(self, force: bool = False) -> None:
        """Download all external data sources."""
        logger.info("Downloading all data sources...")

        # Download in order of dependencies
        sources = [
            ("CWE", self.cwe_downloader.download),
            ("CAPEC", self.capec_downloader.download),
            ("ATT&CK", self.attack_downloader.download),
            ("EPSS", self.epss.download),
            ("KEV", self.kev.download),
            ("Sigma", self.sigma.download),
            ("Nuclei", self.nuclei.download),
        ]

        for name, download_func in sources:
            try:
                logger.info(f"Downloading {name}...")
                download_func(force=force)
                logger.info(f"{name} downloaded successfully")
            except Exception as e:
                logger.error(f"Failed to download {name}: {e}")
                raise

        logger.info("All data sources downloaded successfully")

    def update_mappings(self, force_download: bool = False) -> None:
        """Download sources and update all mapping tables."""
        logger.info("Updating mapping tables...")

        # Download sources
        self.download_all_sources(force=force_download)

        # Initialize parsers
        cwe_path = self.cwe_downloader.get_xml_path()
        capec_path = self.capec_downloader.get_xml_path()
        attack_path = self.attack_downloader.get_json_path()

        if not all([cwe_path, capec_path, attack_path]):
            raise RuntimeError("Not all required files are available")

        self._cwe_parser = CWEParser(cwe_path)
        self._capec_parser = CAPECParser(capec_path)
        self._attack_parser = ATTACKParser(attack_path)

        # Clear existing mappings
        logger.info("Clearing existing mapping tables...")
        self.db.clear_mapping_tables()

        # Insert CWE details
        logger.info("Parsing and inserting CWE details...")
        cwe_details = self._cwe_parser.get_cwe_details()
        self.db.insert_cwe_details(cwe_details)
        logger.info(f"Inserted {len(cwe_details)} CWE entries")

        # Insert CWE -> CAPEC mappings
        logger.info("Parsing and inserting CWE->CAPEC mappings...")
        cwe_capec_mappings = self._cwe_parser.get_cwe_capec_mappings()
        self.db.insert_cwe_capec_mappings(cwe_capec_mappings)
        logger.info(f"Inserted {len(cwe_capec_mappings)} CWE->CAPEC mappings")

        # Insert CAPEC -> Technique mappings
        logger.info("Parsing and inserting CAPEC->Technique mappings...")
        capec_tech_mappings = self._capec_parser.get_capec_technique_mappings()
        self.db.insert_capec_technique_mappings(capec_tech_mappings)
        logger.info(f"Inserted {len(capec_tech_mappings)} CAPEC->Technique mappings")

        # Insert Technique -> Tactic mappings
        logger.info("Parsing and inserting Technique->Tactic mappings...")
        tech_tactic_mappings = self._attack_parser.get_technique_tactic_mappings()
        self.db.insert_technique_tactic_mappings(tech_tactic_mappings)
        logger.info(f"Inserted {len(tech_tactic_mappings)} Technique->Tactic mappings")

        logger.info("All mapping tables updated successfully")

    def enrich_cve(self, cve_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Enrich a CVE with data from all sources.

        Args:
            cve_data: Basic CVE data from NVD

        Returns:
            Enriched CVE data
        """
        cve_id = cve_data.get("cve_id")
        if not cve_id:
            logger.warning("CVE data missing cve_id")
            return cve_data

        enriched = cve_data.copy()

        # Get all CWE IDs (a CVE can have multiple CWEs)
        cwe_ids = enriched.get("cwe_ids", [])

        if cwe_ids:
            # Get CWE names for all CWEs
            cwe_names = []
            for cid in cwe_ids:
                name = self.db.get_cwe_name(cid)
                if name:
                    cwe_names.append(name)
                else:
                    cwe_names.append(cid)  # Fallback to ID if name not found

            enriched["cwe_ids"] = cwe_ids
            enriched["cwe_names"] = cwe_names

            # Get enrichment chain for ALL CWEs (CAPEC -> Technique -> Tactic)
            all_capec_ids = set()
            all_technique_ids = set()
            all_technique_names = set()
            all_tactic_ids = set()
            all_tactic_names = set()

            for cid in cwe_ids:
                chain = self.db.get_full_chain_for_cwe(cid)
                all_capec_ids.update(chain["capec_ids"])
                all_technique_ids.update(chain["technique_ids"])
                all_technique_names.update(chain["technique_names"])
                all_tactic_ids.update(chain["tactic_ids"])
                all_tactic_names.update(chain["tactic_names"])

            enriched["capec_ids"] = sorted(all_capec_ids)
            enriched["technique_ids"] = sorted(all_technique_ids)
            enriched["technique_names"] = sorted(all_technique_names)
            enriched["tactic_ids"] = sorted(all_tactic_ids)
            enriched["tactic_names"] = sorted(all_tactic_names)
        else:
            enriched["cwe_ids"] = []
            enriched["cwe_names"] = []
            enriched["capec_ids"] = []
            enriched["technique_ids"] = []
            enriched["technique_names"] = []
            enriched["tactic_ids"] = []
            enriched["tactic_names"] = []

        # Get EPSS score
        epss_data = self.epss.get_score(cve_id)
        if epss_data:
            enriched["epss_score"] = epss_data.get("epss")
            enriched["epss_percentile"] = epss_data.get("percentile")
        else:
            enriched["epss_score"] = None
            enriched["epss_percentile"] = None

        # Get KEV data
        kev_data = self.kev.get_kev_details(cve_id)
        if kev_data:
            enriched["in_kev"] = True
            enriched["kev_date_added"] = kev_data.get("date_added")
            enriched["kev_due_date"] = kev_data.get("due_date")
            enriched["kev_ransomware_use"] = kev_data.get("ransomware_use", False)
        else:
            enriched["in_kev"] = False
            enriched["kev_date_added"] = None
            enriched["kev_due_date"] = None
            enriched["kev_ransomware_use"] = None

        # Get Sigma detection rules
        sigma_rules = self._get_sigma_rules(cve_id)
        if sigma_rules:
            enriched["has_detection_rules"] = True
            enriched["detection_rules_count"] = len(sigma_rules)
            enriched["detection_rules"] = sigma_rules
        else:
            enriched["has_detection_rules"] = False
            enriched["detection_rules_count"] = 0
            enriched["detection_rules"] = []

        # Get Nuclei templates
        nuclei_templates = self._get_nuclei_templates(cve_id)
        if nuclei_templates:
            enriched["has_nuclei_template"] = True
            enriched["nuclei_template_count"] = len(nuclei_templates)
            enriched["nuclei_templates"] = nuclei_templates
        else:
            enriched["has_nuclei_template"] = False
            enriched["nuclei_template_count"] = 0
            enriched["nuclei_templates"] = []

        return enriched

    def _get_sigma_rules(self, cve_id: str) -> List[Dict[str, Any]]:
        """
        Get Sigma detection rules for a CVE.
        Lazily initializes the Sigma parser and index on first call.

        Args:
            cve_id: CVE identifier

        Returns:
            List of rule info dicts
        """
        # Lazy load Sigma index
        if self._sigma_parser is None:
            rules_dir = self.sigma.get_rules_dir()
            if not rules_dir:
                logger.debug("Sigma rules not downloaded yet")
                return []
            self._sigma_parser = SigmaParser(rules_dir)
            self._sigma_parser.build_cve_index()

        return self._sigma_parser.get_rules_for_cve(cve_id)

    def _get_nuclei_templates(self, cve_id: str) -> List[Dict[str, Any]]:
        """
        Get Nuclei templates for a CVE.
        Lazily initializes the Nuclei parser and index on first call.

        Args:
            cve_id: CVE identifier

        Returns:
            List of template info dicts
        """
        # Lazy load Nuclei index
        if self._nuclei_parser is None:
            templates_dir = self.nuclei.get_templates_dir()
            if not templates_dir:
                logger.debug("Nuclei templates not downloaded yet")
                return []
            self._nuclei_parser = NucleiParser(templates_dir)
            self._nuclei_parser.build_cve_index()

        return self._nuclei_parser.get_templates_for_cve(cve_id)

    def enrich_single_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """
        Fetch, enrich, and save a single CVE.

        Args:
            cve_id: The CVE identifier (e.g., CVE-2021-44228)

        Returns:
            Enriched CVE data or None if not found
        """
        logger.info(f"Enriching CVE: {cve_id}")

        # Load EPSS and KEV data if not already loaded
        self.epss.load_scores()
        self.kev.load_kev()

        # Fetch from NVD
        cve_data = self.nvd.get_cve(cve_id)
        if not cve_data:
            logger.warning(f"CVE {cve_id} not found in NVD")
            return None

        # Enrich
        enriched = self.enrich_cve(cve_data)

        # Save to database
        if self.db.insert_enriched_cve(enriched):
            logger.info(f"CVE {cve_id} enriched and saved successfully")
        else:
            logger.error(f"Failed to save enriched CVE {cve_id}")

        return enriched

    def enrich_cve_list(
        self,
        cve_ids: List[str],
        batch_size: int = 100
    ) -> int:
        """
        Enrich a list of CVEs.

        Args:
            cve_ids: List of CVE identifiers
            batch_size: Number of CVEs to process before saving

        Returns:
            Number of successfully enriched CVEs
        """
        logger.info(f"Enriching {len(cve_ids)} CVEs...")

        # Load EPSS and KEV data
        logger.info("Loading EPSS scores...")
        self.epss.load_scores()
        logger.info("Loading KEV data...")
        self.kev.load_kev()

        enriched_count = 0
        batch = []

        with tqdm(total=len(cve_ids), desc="Enriching CVEs") as pbar:
            for cve_id in cve_ids:
                try:
                    # Fetch from NVD
                    cve_data = self.nvd.get_cve(cve_id)
                    if not cve_data:
                        logger.warning(f"CVE {cve_id} not found in NVD")
                        pbar.update(1)
                        continue

                    # Enrich
                    enriched = self.enrich_cve(cve_data)
                    batch.append(enriched)

                    # Save batch
                    if len(batch) >= batch_size:
                        self.db.insert_enriched_cves_batch(batch)
                        enriched_count += len(batch)
                        batch = []

                except Exception as e:
                    logger.error(f"Error enriching {cve_id}: {e}")

                pbar.update(1)

        # Save remaining batch
        if batch:
            self.db.insert_enriched_cves_batch(batch)
            enriched_count += len(batch)

        logger.info(f"Successfully enriched {enriched_count}/{len(cve_ids)} CVEs")
        return enriched_count

    def fetch_all(
        self,
        batch_size: int = 500,
        force_download: bool = False,
    ) -> int:
        """
        Fetch and enrich all CVEs from NVD JSON Feeds (bulk download).

        This is much faster than using the API for initial population.
        Downloads yearly feed files and processes them in bulk.

        Args:
            batch_size: Number of CVEs to process before saving to database
            force_download: Force re-download of feed files

        Returns:
            Number of successfully enriched CVEs
        """
        logger.info("Starting bulk CVE fetch from NVD Feeds...")

        # Load EPSS and KEV data
        logger.info("Loading EPSS scores...")
        self.epss.download(force=force_download)
        self.epss.load_scores()
        logger.info("Loading KEV data...")
        self.kev.download(force=force_download)
        self.kev.load_kev()

        # Download all yearly feeds
        logger.info("Downloading NVD yearly feeds...")
        years = self.nvd_feeds.get_available_years()

        enriched_count = 0
        batch = []

        for year in years:
            logger.info(f"Processing year {year}...")
            feed_path = self.nvd_feeds.download_year(year, force=force_download)

            if not feed_path:
                logger.warning(f"Failed to download feed for {year}, skipping...")
                continue

            # Load all CVEs into memory (single parse)
            cve_list = list(self.nvd_feeds.parse_feed(feed_path))

            with tqdm(total=len(cve_list), desc=f"Enriching {year}") as pbar:
                for cve_data in cve_list:
                    try:
                        # Enrich
                        enriched = self.enrich_cve(cve_data)
                        batch.append(enriched)

                        # Save batch
                        if len(batch) >= batch_size:
                            self.db.insert_enriched_cves_batch(batch)
                            enriched_count += len(batch)
                            batch = []

                    except Exception as e:
                        logger.error(f"Error enriching CVE {cve_data.get('cve_id')}: {e}")

                    pbar.update(1)

        # Save remaining batch
        if batch:
            self.db.insert_enriched_cves_batch(batch)
            enriched_count += len(batch)

        logger.info(f"Bulk fetch complete. Total enriched: {enriched_count}")
        return enriched_count

    def update(
        self,
        batch_size: int = 100,
        force_download: bool = False,
    ) -> int:
        """
        Update CVEs using NVD API based on last modification date.

        Fetches only CVEs modified since the last update in the database.
        Uses the NVD API with lastModStartDate filter.

        Args:
            batch_size: Number of CVEs to process before saving to database
            force_download: Force re-download of EPSS/KEV data

        Returns:
            Number of updated CVEs
        """
        logger.info("Starting incremental CVE update...")

        # Get last modified date from database
        last_modified = self.db.get_last_modified()

        if last_modified is None:
            logger.error(
                "No CVEs in database. Please run 'fetch' first to populate the database."
            )
            return 0

        logger.info(f"Last modified CVE date in database: {last_modified.isoformat()}")

        # Load EPSS and KEV data
        logger.info("Loading EPSS scores...")
        self.epss.download(force=force_download)
        self.epss.load_scores()
        logger.info("Loading KEV data...")
        self.kev.download(force=force_download)
        self.kev.load_kev()

        # Fetch modified CVEs from API
        updated_count = 0
        batch = []

        with tqdm(desc="Updating CVEs from NVD API") as pbar:
            for cve_data in self.nvd.get_modified_cves(since=last_modified):
                try:
                    # Enrich
                    enriched = self.enrich_cve(cve_data)
                    batch.append(enriched)

                    # Save batch
                    if len(batch) >= batch_size:
                        self.db.insert_enriched_cves_batch(batch)
                        updated_count += len(batch)
                        batch = []

                except Exception as e:
                    logger.error(f"Error updating CVE {cve_data.get('cve_id')}: {e}")

                pbar.update(1)

        # Save remaining batch
        if batch:
            self.db.insert_enriched_cves_batch(batch)
            updated_count += len(batch)

        logger.info(f"Update complete. Total updated: {updated_count}")
        return updated_count

    def update_epss_scores(
        self,
        batch_size: int = 1000,
        force_download: bool = False,
    ) -> int:
        """
        Update only EPSS scores for all existing CVEs in database.

        Downloads fresh EPSS data and updates scores without touching other fields.

        Args:
            batch_size: Number of CVEs to update per batch
            force_download: Force re-download of EPSS data

        Returns:
            Number of updated CVEs
        """
        logger.info("Starting EPSS scores update...")

        # Download and load fresh EPSS data
        logger.info("Downloading fresh EPSS scores...")
        self.epss.download(force=force_download)
        epss_scores = self.epss.load_scores(force_reload=True)

        if not epss_scores:
            logger.error("No EPSS scores available")
            return 0

        # Get all CVE IDs from database
        all_cve_ids = self.db.get_all_cve_ids()
        logger.info(f"Found {len(all_cve_ids)} CVEs in database")

        updated_count = 0
        batch = []

        with tqdm(total=len(all_cve_ids), desc="Updating EPSS scores") as pbar:
            for cve_id in all_cve_ids:
                epss_data = epss_scores.get(cve_id)
                if epss_data:
                    batch.append((
                        cve_id,
                        epss_data.get("epss"),
                        epss_data.get("percentile")
                    ))
                else:
                    # No EPSS data - set to NULL
                    batch.append((cve_id, None, None))

                if len(batch) >= batch_size:
                    self.db.update_epss_scores_batch(batch)
                    updated_count += len(batch)
                    batch = []

                pbar.update(1)

        # Process remaining batch
        if batch:
            self.db.update_epss_scores_batch(batch)
            updated_count += len(batch)

        logger.info(f"EPSS update complete. Total updated: {updated_count}")
        return updated_count

    def update_kev_status(
        self,
        batch_size: int = 1000,
        force_download: bool = False,
    ) -> int:
        """
        Update only KEV status for all existing CVEs in database.

        Downloads fresh KEV data and updates status without touching other fields.
        CVEs not in current KEV list will have in_kev set to FALSE.

        Args:
            batch_size: Number of CVEs to update per batch
            force_download: Force re-download of KEV data

        Returns:
            Number of updated CVEs
        """
        logger.info("Starting KEV status update...")

        # Download and load fresh KEV data
        logger.info("Downloading fresh KEV data...")
        self.kev.download(force=force_download)
        kev_data = self.kev.load_kev(force_reload=True)

        if kev_data is None:
            logger.error("Failed to load KEV data")
            return 0

        logger.info(f"Loaded {len(kev_data)} CVEs from KEV catalog")

        # Get all CVE IDs from database
        all_cve_ids = self.db.get_all_cve_ids()
        logger.info(f"Found {len(all_cve_ids)} CVEs in database")

        updated_count = 0
        batch = []

        with tqdm(total=len(all_cve_ids), desc="Updating KEV status") as pbar:
            for cve_id in all_cve_ids:
                kev_info = kev_data.get(cve_id)
                if kev_info:
                    batch.append((
                        cve_id,
                        True,
                        kev_info.get("date_added"),
                        kev_info.get("due_date"),
                        kev_info.get("ransomware_use", False)
                    ))
                else:
                    # Not in KEV - set to FALSE
                    batch.append((cve_id, False, None, None, None))

                if len(batch) >= batch_size:
                    self.db.update_kev_status_batch(batch)
                    updated_count += len(batch)
                    batch = []

                pbar.update(1)

        # Process remaining batch
        if batch:
            self.db.update_kev_status_batch(batch)
            updated_count += len(batch)

        logger.info(f"KEV update complete. Total updated: {updated_count}")
        return updated_count

    def update_sigma_rules(
        self,
        batch_size: int = 1000,
        force_download: bool = False,
    ) -> int:
        """
        Update Sigma detection rules for all existing CVEs in database.

        Downloads SigmaHQ repository, parses rules to find CVE references,
        and updates the detection_rules fields for matching CVEs.

        Args:
            batch_size: Number of CVEs to update per batch
            force_download: Force re-download of Sigma rules

        Returns:
            Number of updated CVEs
        """
        import json

        logger.info("Starting Sigma rules update...")

        # Download and extract Sigma rules
        logger.info("Downloading Sigma rules from SigmaHQ...")
        self.sigma.download(force=force_download)

        rules_dir = self.sigma.get_rules_dir()
        if not rules_dir:
            logger.error("Sigma rules directory not found")
            return 0

        # Initialize parser and build index
        self._sigma_parser = SigmaParser(rules_dir)
        cve_index = self._sigma_parser.build_cve_index()

        logger.info(f"Found {len(cve_index)} CVEs with Sigma rules")

        # Get all CVE IDs from database
        all_cve_ids = self.db.get_all_cve_ids()
        logger.info(f"Found {len(all_cve_ids)} CVEs in database")

        updated_count = 0
        batch = []

        with tqdm(total=len(all_cve_ids), desc="Updating Sigma rules") as pbar:
            for cve_id in all_cve_ids:
                rules = cve_index.get(cve_id, [])
                if rules:
                    batch.append((
                        cve_id,
                        True,
                        len(rules),
                        json.dumps(rules)
                    ))
                else:
                    # No rules - set to FALSE
                    batch.append((cve_id, False, 0, json.dumps([])))

                if len(batch) >= batch_size:
                    self.db.update_sigma_rules_batch(batch)
                    updated_count += len(batch)
                    batch = []

                pbar.update(1)

        # Process remaining batch
        if batch:
            self.db.update_sigma_rules_batch(batch)
            updated_count += len(batch)

        # Log stats
        stats = self._sigma_parser.get_stats()
        logger.info(
            f"Sigma update complete. Total updated: {updated_count}, "
            f"CVEs with rules: {stats['unique_cves']}"
        )
        return updated_count

    def update_nuclei_templates(
        self,
        batch_size: int = 1000,
        force_download: bool = False,
    ) -> int:
        """
        Update Nuclei templates for all existing CVEs in database.

        Downloads Nuclei templates repository, parses templates to find CVE references,
        and updates the nuclei_templates fields for matching CVEs.

        Args:
            batch_size: Number of CVEs to update per batch
            force_download: Force re-download of Nuclei templates

        Returns:
            Number of updated CVEs
        """
        import json

        logger.info("Starting Nuclei templates update...")

        # Download and extract Nuclei templates
        logger.info("Downloading Nuclei templates from ProjectDiscovery...")
        self.nuclei.download(force=force_download)

        templates_dir = self.nuclei.get_templates_dir()
        if not templates_dir:
            logger.error("Nuclei templates directory not found")
            return 0

        # Initialize parser and build index
        self._nuclei_parser = NucleiParser(templates_dir)
        cve_index = self._nuclei_parser.build_cve_index()

        logger.info(f"Found {len(cve_index)} CVEs with Nuclei templates")

        # Get all CVE IDs from database
        all_cve_ids = self.db.get_all_cve_ids()
        logger.info(f"Found {len(all_cve_ids)} CVEs in database")

        updated_count = 0
        batch = []

        with tqdm(total=len(all_cve_ids), desc="Updating Nuclei templates") as pbar:
            for cve_id in all_cve_ids:
                templates = cve_index.get(cve_id, [])
                if templates:
                    batch.append((
                        cve_id,
                        True,
                        len(templates),
                        json.dumps(templates)
                    ))
                else:
                    # No templates - set to FALSE
                    batch.append((cve_id, False, 0, json.dumps([])))

                if len(batch) >= batch_size:
                    self.db.update_nuclei_templates_batch(batch)
                    updated_count += len(batch)
                    batch = []

                pbar.update(1)

        # Process remaining batch
        if batch:
            self.db.update_nuclei_templates_batch(batch)
            updated_count += len(batch)

        # Log stats
        stats = self._nuclei_parser.get_stats()
        logger.info(
            f"Nuclei update complete. Total updated: {updated_count}, "
            f"CVEs with templates: {stats['unique_cves']}, "
            f"Verified templates: {stats['verified_templates']}"
        )
        return updated_count

    def get_enrichment_stats(self) -> Dict[str, Any]:
        """Get statistics about the enrichment database."""
        from database.schema import get_table_count

        stats = {
            "total_cves": self.db.get_cve_count(),
            "cwe_count": get_table_count("cwe_details"),
            "cwe_capec_mappings": get_table_count("map_cwe_capec"),
            "capec_technique_mappings": get_table_count("map_capec_technique"),
            "technique_tactic_mappings": get_table_count("map_technique_tactic"),
            "kev_cves": len(self.db.get_kev_cves()),
            "cves_with_detection_rules": len(self.db.get_cves_with_detection_rules()),
            "cves_with_nuclei_templates": len(self.db.get_cves_with_nuclei_templates()),
        }

        return stats

    def print_enriched_cve(self, cve_id: str) -> None:
        """Print enriched CVE data in a readable format."""
        cve = self.db.get_enriched_cve(cve_id)

        if not cve:
            print(f"CVE {cve_id} not found in database")
            return

        print(f"\n{'='*60}")
        print(f"CVE ID: {cve['cve_id']}")
        print(f"{'='*60}")

        if cve.get('description'):
            desc = cve['description'][:200] + "..." if len(cve['description']) > 200 else cve['description']
            print(f"\nDescription: {desc}")

        print(f"\nPublished: {cve.get('published_date')}")
        print(f"Last Modified: {cve.get('last_modified')}")
        print(f"Status: {cve.get('vuln_status', 'N/A')}")

        print(f"\n--- CVSS ---")
        cvss_version = cve.get('cvss_version', 'N/A')
        print(f"Version: {cvss_version}")
        print(f"Score: {cve.get('cvss_score')} ({cve.get('cvss_severity')})")
        print(f"Vector: {cve.get('cvss_vector')}")

        print(f"\n--- CWE ---")
        cwe_ids = cve.get('cwe_ids', [])
        cwe_names = cve.get('cwe_names', [])
        if cwe_ids:
            for i, cid in enumerate(cwe_ids):
                name = cwe_names[i] if i < len(cwe_names) else "Unknown"
                print(f"  {cid}: {name}")
        else:
            print(f"  None")

        print(f"\n--- MITRE Chain ---")
        print(f"CAPEC IDs: {', '.join(cve.get('capec_ids', [])) or 'None'}")
        print(f"Techniques: {', '.join(cve.get('technique_ids', [])) or 'None'}")
        print(f"Tactics: {', '.join(cve.get('tactic_names', [])) or 'None'}")

        print(f"\n--- EPSS ---")
        if cve.get('epss_score') is not None:
            print(f"Score: {cve['epss_score']:.4f} (Percentile: {cve.get('epss_percentile', 0):.4f})")
        else:
            print("Score: Not available")

        print(f"\n--- Exploit/Patch ---")
        if cve.get('has_exploit'):
            print(f"Has Exploit: Yes ({cve.get('exploit_count', 0)} references)")
        else:
            print("Has Exploit: No")
        print(f"Has Patch: {'Yes' if cve.get('has_patch') else 'No'}")

        print(f"\n--- CPE (Affected Products) ---")
        cpe_list = cve.get('cpe', [])
        if cpe_list and isinstance(cpe_list, list):
            for cpe in cpe_list[:5]:  # Show max 5
                print(f"  - {cpe}")
            if len(cpe_list) > 5:
                print(f"  ... and {len(cpe_list) - 5} more")
        else:
            print("  None")

        print(f"\n--- KEV ---")
        if cve.get('in_kev'):
            print(f"In KEV: Yes")
            print(f"Date Added: {cve.get('kev_date_added')}")
            print(f"Due Date: {cve.get('kev_due_date')}")
            print(f"Ransomware Use: {'Yes' if cve.get('kev_ransomware_use') else 'No'}")
        else:
            print("In KEV: No")

        print(f"\n--- Detection Rules (Sigma) ---")
        if cve.get('has_detection_rules'):
            rules_count = cve.get('detection_rules_count', 0)
            print(f"Has Rules: Yes ({rules_count} rule{'s' if rules_count != 1 else ''})")
            rules = cve.get('detection_rules', [])
            if rules and isinstance(rules, list):
                for rule in rules[:5]:  # Show max 5
                    level = rule.get('level', 'unknown')
                    title = rule.get('title', 'Unknown')
                    print(f"  - [{level}] {title}")
                if len(rules) > 5:
                    print(f"  ... and {len(rules) - 5} more")
        else:
            print("Has Rules: No")

        print(f"\n--- Exploit Templates (Nuclei) ---")
        if cve.get('has_nuclei_template'):
            template_count = cve.get('nuclei_template_count', 0)
            print(f"Has Templates: Yes ({template_count} template{'s' if template_count != 1 else ''})")
            templates = cve.get('nuclei_templates', [])
            if templates and isinstance(templates, list):
                for tmpl in templates[:5]:  # Show max 5
                    severity = tmpl.get('severity', 'unknown')
                    name = tmpl.get('name', 'Unknown')
                    verified = " (verified)" if tmpl.get('verified') else ""
                    print(f"  - [{severity}] {name}{verified}")
                if len(templates) > 5:
                    print(f"  ... and {len(templates) - 5} more")
        else:
            print("Has Templates: No")

        print(f"\nReferences: {cve.get('reference_count', 0)}")
        print(f"Last Enriched: {cve.get('last_enriched_at')}")
        print(f"{'='*60}\n")
