"""
Database CRUD operations for CVE Enrichment System.
"""

import json
import logging
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
from contextlib import contextmanager

import mariadb

from .schema import get_db_connection

logger = logging.getLogger(__name__)


class DatabaseManager:
    """Manager class for database operations."""

    def __init__(self):
        self._conn = None

    @contextmanager
    def connection(self):
        """Context manager for database connections."""
        conn = get_db_connection()
        try:
            yield conn
        finally:
            conn.close()

    @contextmanager
    def cursor(self, conn: Optional[mariadb.Connection] = None):
        """Context manager for database cursors."""
        if conn is None:
            with self.connection() as conn:
                cursor = conn.cursor()
                try:
                    yield cursor, conn
                finally:
                    cursor.close()
        else:
            cursor = conn.cursor()
            try:
                yield cursor, conn
            finally:
                cursor.close()

    # ==================== CWE Details Operations ====================

    def insert_cwe_details(self, cwe_data: List[Dict[str, str]]) -> int:
        """Insert or update CWE details in bulk."""
        if not cwe_data:
            return 0

        sql = """
            INSERT INTO cwe_details (cwe_id, cwe_name, description)
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE
                cwe_name = VALUES(cwe_name),
                description = VALUES(description)
        """

        inserted = 0
        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                for cwe in cwe_data:
                    cursor.execute(sql, (
                        cwe.get("cwe_id"),
                        cwe.get("cwe_name"),
                        cwe.get("description")
                    ))
                    inserted += 1
                conn.commit()
                logger.info(f"Inserted/updated {inserted} CWE details")
            except mariadb.Error as e:
                logger.error(f"Error inserting CWE details: {e}")
                conn.rollback()
                raise
            finally:
                cursor.close()

        return inserted

    def get_cwe_name(self, cwe_id: str) -> Optional[str]:
        """Get CWE name by ID."""
        with self.cursor() as (cursor, conn):
            cursor.execute(
                "SELECT cwe_name FROM cwe_details WHERE cwe_id = ?",
                (cwe_id,)
            )
            result = cursor.fetchone()
            return result[0] if result else None

    # ==================== Mapping Tables Operations ====================

    def clear_mapping_tables(self) -> None:
        """Clear all mapping tables for fresh import."""
        tables = ["map_cwe_capec", "map_capec_technique", "map_technique_tactic"]
        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                for table in tables:
                    cursor.execute(f"TRUNCATE TABLE {table}")
                conn.commit()
                logger.info("All mapping tables cleared")
            except mariadb.Error as e:
                logger.error(f"Error clearing mapping tables: {e}")
                conn.rollback()
                raise
            finally:
                cursor.close()

    def insert_cwe_capec_mappings(self, mappings: List[Tuple[str, str]]) -> int:
        """Insert CWE to CAPEC mappings in bulk."""
        if not mappings:
            return 0

        sql = """
            INSERT IGNORE INTO map_cwe_capec (cwe_id, capec_id)
            VALUES (?, ?)
        """

        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.executemany(sql, mappings)
                conn.commit()
                inserted = cursor.rowcount
                logger.info(f"Inserted {inserted} CWE-CAPEC mappings")
                return inserted
            except mariadb.Error as e:
                logger.error(f"Error inserting CWE-CAPEC mappings: {e}")
                conn.rollback()
                raise
            finally:
                cursor.close()

    def insert_capec_technique_mappings(
        self, mappings: List[Tuple[str, str, str]]
    ) -> int:
        """Insert CAPEC to Technique mappings in bulk."""
        if not mappings:
            return 0

        sql = """
            INSERT INTO map_capec_technique (capec_id, technique_id, technique_name)
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE technique_name = VALUES(technique_name)
        """

        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.executemany(sql, mappings)
                conn.commit()
                inserted = cursor.rowcount
                logger.info(f"Inserted {inserted} CAPEC-Technique mappings")
                return inserted
            except mariadb.Error as e:
                logger.error(f"Error inserting CAPEC-Technique mappings: {e}")
                conn.rollback()
                raise
            finally:
                cursor.close()

    def insert_technique_tactic_mappings(
        self, mappings: List[Tuple[str, str, str]]
    ) -> int:
        """Insert Technique to Tactic mappings in bulk."""
        if not mappings:
            return 0

        sql = """
            INSERT INTO map_technique_tactic (technique_id, tactic_id, tactic_name)
            VALUES (?, ?, ?)
            ON DUPLICATE KEY UPDATE tactic_name = VALUES(tactic_name)
        """

        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.executemany(sql, mappings)
                conn.commit()
                inserted = cursor.rowcount
                logger.info(f"Inserted {inserted} Technique-Tactic mappings")
                return inserted
            except mariadb.Error as e:
                logger.error(f"Error inserting Technique-Tactic mappings: {e}")
                conn.rollback()
                raise
            finally:
                cursor.close()

    # ==================== Enrichment Chain Queries ====================

    def get_capec_for_cwe(self, cwe_id: str) -> List[str]:
        """Get CAPEC IDs for a given CWE."""
        with self.cursor() as (cursor, conn):
            cursor.execute(
                "SELECT capec_id FROM map_cwe_capec WHERE cwe_id = ?",
                (cwe_id,)
            )
            return [row[0] for row in cursor.fetchall()]

    def get_techniques_for_capec(self, capec_id: str) -> List[Tuple[str, str]]:
        """Get Technique IDs and names for a given CAPEC."""
        with self.cursor() as (cursor, conn):
            cursor.execute(
                "SELECT technique_id, technique_name FROM map_capec_technique "
                "WHERE capec_id = ?",
                (capec_id,)
            )
            return cursor.fetchall()

    def get_tactics_for_technique(self, technique_id: str) -> List[Tuple[str, str]]:
        """Get Tactic IDs and names for a given Technique."""
        with self.cursor() as (cursor, conn):
            cursor.execute(
                "SELECT tactic_id, tactic_name FROM map_technique_tactic "
                "WHERE technique_id = ?",
                (technique_id,)
            )
            return cursor.fetchall()

    def get_full_chain_for_cwe(self, cwe_id: str) -> Dict[str, Any]:
        """Get the complete enrichment chain for a CWE."""
        chain = {
            "capec_ids": set(),
            "technique_ids": set(),
            "technique_names": set(),
            "tactic_ids": set(),
            "tactic_names": set(),
        }

        capec_ids = self.get_capec_for_cwe(cwe_id)
        chain["capec_ids"].update(capec_ids)

        for capec_id in capec_ids:
            techniques = self.get_techniques_for_capec(capec_id)
            for tech_id, tech_name in techniques:
                chain["technique_ids"].add(tech_id)
                if tech_name:
                    chain["technique_names"].add(tech_name)

                tactics = self.get_tactics_for_technique(tech_id)
                for tactic_id, tactic_name in tactics:
                    chain["tactic_ids"].add(tactic_id)
                    if tactic_name:
                        chain["tactic_names"].add(tactic_name)

        # Convert sets to sorted lists
        chain["capec_ids"] = sorted(chain["capec_ids"])
        chain["technique_ids"] = sorted(chain["technique_ids"])
        chain["technique_names"] = sorted(chain["technique_names"])
        chain["tactic_ids"] = sorted(chain["tactic_ids"])
        chain["tactic_names"] = sorted(chain["tactic_names"])

        return chain

    # ==================== CVE Enriched Operations ====================

    def insert_enriched_cve(self, cve_data: Dict[str, Any]) -> bool:
        """Insert or update an enriched CVE."""
        sql = """
            INSERT INTO cve_enriched (
                cve_id, description, published_date, last_modified,
                cvss_score, cvss_vector, cvss_severity, cvss_version,
                vuln_status,
                cwe_ids, cwe_names,
                capec_ids, technique_ids, technique_names,
                tactic_ids, tactic_names,
                epss_score, epss_percentile,
                in_kev, kev_date_added, kev_due_date, kev_ransomware_use,
                has_exploit, exploit_count, has_patch, reference_count,
                affected_vendors, affected_products, affected_products_detail,
                has_detection_rules, detection_rules_count, detection_rules,
                has_nuclei_template, nuclei_template_count, nuclei_templates,
                has_snort_rules, snort_rules_count, snort_rules,
                last_enriched_at
            ) VALUES (
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?,
                ?, ?,
                ?, ?, ?,
                ?, ?,
                ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?,
                NOW()
            )
            ON DUPLICATE KEY UPDATE
                description = VALUES(description),
                published_date = VALUES(published_date),
                last_modified = VALUES(last_modified),
                cvss_score = VALUES(cvss_score),
                cvss_vector = VALUES(cvss_vector),
                cvss_severity = VALUES(cvss_severity),
                cvss_version = VALUES(cvss_version),
                vuln_status = VALUES(vuln_status),
                cwe_ids = VALUES(cwe_ids),
                cwe_names = VALUES(cwe_names),
                capec_ids = VALUES(capec_ids),
                technique_ids = VALUES(technique_ids),
                technique_names = VALUES(technique_names),
                tactic_ids = VALUES(tactic_ids),
                tactic_names = VALUES(tactic_names),
                epss_score = VALUES(epss_score),
                epss_percentile = VALUES(epss_percentile),
                in_kev = VALUES(in_kev),
                kev_date_added = VALUES(kev_date_added),
                kev_due_date = VALUES(kev_due_date),
                kev_ransomware_use = VALUES(kev_ransomware_use),
                has_exploit = VALUES(has_exploit),
                exploit_count = VALUES(exploit_count),
                has_patch = VALUES(has_patch),
                reference_count = VALUES(reference_count),
                affected_vendors = VALUES(affected_vendors),
                affected_products = VALUES(affected_products),
                affected_products_detail = VALUES(affected_products_detail),
                has_detection_rules = VALUES(has_detection_rules),
                detection_rules_count = VALUES(detection_rules_count),
                detection_rules = VALUES(detection_rules),
                has_nuclei_template = VALUES(has_nuclei_template),
                nuclei_template_count = VALUES(nuclei_template_count),
                nuclei_templates = VALUES(nuclei_templates),
                has_snort_rules = VALUES(has_snort_rules),
                snort_rules_count = VALUES(snort_rules_count),
                snort_rules = VALUES(snort_rules),
                last_enriched_at = NOW()
        """

        # Convert lists to JSON strings
        cwe_ids = json.dumps(cve_data.get("cwe_ids", []))
        cwe_names = json.dumps(cve_data.get("cwe_names", []))
        capec_ids = json.dumps(cve_data.get("capec_ids", []))
        technique_ids = json.dumps(cve_data.get("technique_ids", []))
        technique_names = json.dumps(cve_data.get("technique_names", []))
        tactic_ids = json.dumps(cve_data.get("tactic_ids", []))
        tactic_names = json.dumps(cve_data.get("tactic_names", []))
        affected_vendors = json.dumps(cve_data.get("affected_vendors", []))
        affected_products = json.dumps(cve_data.get("affected_products", []))
        affected_products_detail = json.dumps(cve_data.get("affected_products_detail", []))
        detection_rules = json.dumps(cve_data.get("detection_rules", []))
        nuclei_templates = json.dumps(cve_data.get("nuclei_templates", []))
        snort_rules = json.dumps(cve_data.get("snort_rules", []))

        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.execute(sql, (
                    cve_data.get("cve_id"),
                    cve_data.get("description"),
                    cve_data.get("published_date"),
                    cve_data.get("last_modified"),
                    cve_data.get("cvss_score"),
                    cve_data.get("cvss_vector"),
                    cve_data.get("cvss_severity"),
                    cve_data.get("cvss_version"),
                    cve_data.get("vuln_status"),
                    cwe_ids,
                    cwe_names,
                    capec_ids,
                    technique_ids,
                    technique_names,
                    tactic_ids,
                    tactic_names,
                    cve_data.get("epss_score"),
                    cve_data.get("epss_percentile"),
                    cve_data.get("in_kev", False),
                    cve_data.get("kev_date_added"),
                    cve_data.get("kev_due_date"),
                    cve_data.get("kev_ransomware_use"),
                    cve_data.get("has_exploit", False),
                    cve_data.get("exploit_count", 0),
                    cve_data.get("has_patch", False),
                    cve_data.get("reference_count", 0),
                    affected_vendors,
                    affected_products,
                    affected_products_detail,
                    cve_data.get("has_detection_rules", False),
                    cve_data.get("detection_rules_count", 0),
                    detection_rules,
                    cve_data.get("has_nuclei_template", False),
                    cve_data.get("nuclei_template_count", 0),
                    nuclei_templates,
                    cve_data.get("has_snort_rules", False),
                    cve_data.get("snort_rules_count", 0),
                    snort_rules,
                ))
                conn.commit()
                return True
            except mariadb.Error as e:
                logger.error(f"Error inserting enriched CVE {cve_data.get('cve_id')}: {e}")
                conn.rollback()
                return False
            finally:
                cursor.close()

    def insert_enriched_cves_batch(self, cves: List[Dict[str, Any]]) -> int:
        """Insert multiple enriched CVEs in a batch."""
        if not cves:
            return 0

        sql = """
            INSERT INTO cve_enriched (
                cve_id, description, published_date, last_modified,
                cvss_score, cvss_vector, cvss_severity, cvss_version,
                vuln_status,
                cwe_ids, cwe_names,
                capec_ids, technique_ids, technique_names,
                tactic_ids, tactic_names,
                epss_score, epss_percentile,
                in_kev, kev_date_added, kev_due_date, kev_ransomware_use,
                has_exploit, exploit_count, has_patch, reference_count,
                affected_vendors, affected_products, affected_products_detail,
                has_detection_rules, detection_rules_count, detection_rules,
                has_nuclei_template, nuclei_template_count, nuclei_templates,
                has_snort_rules, snort_rules_count, snort_rules,
                last_enriched_at
            ) VALUES (
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?,
                ?, ?,
                ?, ?, ?,
                ?, ?,
                ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?,
                ?, ?, ?,
                NOW()
            )
            ON DUPLICATE KEY UPDATE
                description = VALUES(description),
                published_date = VALUES(published_date),
                last_modified = VALUES(last_modified),
                cvss_score = VALUES(cvss_score),
                cvss_vector = VALUES(cvss_vector),
                cvss_severity = VALUES(cvss_severity),
                cvss_version = VALUES(cvss_version),
                vuln_status = VALUES(vuln_status),
                cwe_ids = VALUES(cwe_ids),
                cwe_names = VALUES(cwe_names),
                capec_ids = VALUES(capec_ids),
                technique_ids = VALUES(technique_ids),
                technique_names = VALUES(technique_names),
                tactic_ids = VALUES(tactic_ids),
                tactic_names = VALUES(tactic_names),
                epss_score = VALUES(epss_score),
                epss_percentile = VALUES(epss_percentile),
                in_kev = VALUES(in_kev),
                kev_date_added = VALUES(kev_date_added),
                kev_due_date = VALUES(kev_due_date),
                kev_ransomware_use = VALUES(kev_ransomware_use),
                has_exploit = VALUES(has_exploit),
                exploit_count = VALUES(exploit_count),
                has_patch = VALUES(has_patch),
                reference_count = VALUES(reference_count),
                affected_vendors = VALUES(affected_vendors),
                affected_products = VALUES(affected_products),
                affected_products_detail = VALUES(affected_products_detail),
                has_detection_rules = VALUES(has_detection_rules),
                detection_rules_count = VALUES(detection_rules_count),
                detection_rules = VALUES(detection_rules),
                has_nuclei_template = VALUES(has_nuclei_template),
                nuclei_template_count = VALUES(nuclei_template_count),
                nuclei_templates = VALUES(nuclei_templates),
                has_snort_rules = VALUES(has_snort_rules),
                snort_rules_count = VALUES(snort_rules_count),
                snort_rules = VALUES(snort_rules),
                last_enriched_at = NOW()
        """

        values = []
        for cve in cves:
            values.append((
                cve.get("cve_id"),
                cve.get("description"),
                cve.get("published_date"),
                cve.get("last_modified"),
                cve.get("cvss_score"),
                cve.get("cvss_vector"),
                cve.get("cvss_severity"),
                cve.get("cvss_version"),
                cve.get("vuln_status"),
                json.dumps(cve.get("cwe_ids", [])),
                json.dumps(cve.get("cwe_names", [])),
                json.dumps(cve.get("capec_ids", [])),
                json.dumps(cve.get("technique_ids", [])),
                json.dumps(cve.get("technique_names", [])),
                json.dumps(cve.get("tactic_ids", [])),
                json.dumps(cve.get("tactic_names", [])),
                cve.get("epss_score"),
                cve.get("epss_percentile"),
                cve.get("in_kev", False),
                cve.get("kev_date_added"),
                cve.get("kev_due_date"),
                cve.get("kev_ransomware_use"),
                cve.get("has_exploit", False),
                cve.get("exploit_count", 0),
                cve.get("has_patch", False),
                cve.get("reference_count", 0),
                json.dumps(cve.get("affected_vendors", [])),
                json.dumps(cve.get("affected_products", [])),
                json.dumps(cve.get("affected_products_detail", [])),
                cve.get("has_detection_rules", False),
                cve.get("detection_rules_count", 0),
                json.dumps(cve.get("detection_rules", [])),
                cve.get("has_nuclei_template", False),
                cve.get("nuclei_template_count", 0),
                json.dumps(cve.get("nuclei_templates", [])),
                cve.get("has_snort_rules", False),
                cve.get("snort_rules_count", 0),
                json.dumps(cve.get("snort_rules", [])),
            ))

        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.executemany(sql, values)
                conn.commit()
                return len(values)
            except mariadb.Error as e:
                logger.error(f"Error batch inserting enriched CVEs: {e}")
                conn.rollback()
                raise
            finally:
                cursor.close()

    def get_enriched_cve(self, cve_id: str) -> Optional[Dict[str, Any]]:
        """Get an enriched CVE by ID."""
        sql = "SELECT * FROM cve_enriched WHERE cve_id = ?"

        with self.cursor() as (cursor, conn):
            cursor.execute(sql, (cve_id,))
            row = cursor.fetchone()

            if not row:
                return None

            columns = [desc[0] for desc in cursor.description]
            result = dict(zip(columns, row))

            # Parse JSON fields
            for field in ["cwe_ids", "cwe_names", "capec_ids", "technique_ids",
                          "technique_names", "tactic_ids", "tactic_names",
                          "affected_vendors", "affected_products", "affected_products_detail",
                          "detection_rules", "nuclei_templates", "snort_rules",
                          "kill_chain_phases", "prerequisites", "capabilities"]:
                if result.get(field):
                    try:
                        result[field] = json.loads(result[field])
                    except (json.JSONDecodeError, TypeError):
                        result[field] = []

            return result

    def cve_exists(self, cve_id: str) -> bool:
        """Check if a CVE exists in the enriched table."""
        with self.cursor() as (cursor, conn):
            cursor.execute(
                "SELECT 1 FROM cve_enriched WHERE cve_id = ?",
                (cve_id,)
            )
            return cursor.fetchone() is not None

    def get_all_cve_ids(self) -> List[str]:
        """Get all CVE IDs from the enriched table."""
        with self.cursor() as (cursor, conn):
            cursor.execute("SELECT cve_id FROM cve_enriched ORDER BY cve_id")
            return [row[0] for row in cursor.fetchall()]

    def get_cve_count(self) -> int:
        """Get the total count of enriched CVEs."""
        with self.cursor() as (cursor, conn):
            cursor.execute("SELECT COUNT(*) FROM cve_enriched")
            result = cursor.fetchone()
            return result[0] if result else 0

    def get_kev_cves(self) -> List[str]:
        """Get all CVE IDs that are in KEV."""
        with self.cursor() as (cursor, conn):
            cursor.execute(
                "SELECT cve_id FROM cve_enriched WHERE in_kev = TRUE"
            )
            return [row[0] for row in cursor.fetchall()]

    def get_high_risk_cves(
        self,
        min_cvss: float = 7.0,
        min_epss: float = 0.1
    ) -> List[Dict[str, Any]]:
        """Get high-risk CVEs based on CVSS and EPSS scores."""
        sql = """
            SELECT cve_id, cvss_v3_score, epss_score, in_kev
            FROM cve_enriched
            WHERE cvss_v3_score >= ? OR epss_score >= ? OR in_kev = TRUE
            ORDER BY
                in_kev DESC,
                epss_score DESC,
                cvss_v3_score DESC
        """

        with self.cursor() as (cursor, conn):
            cursor.execute(sql, (min_cvss, min_epss))
            columns = ["cve_id", "cvss_v3_score", "epss_score", "in_kev"]
            return [dict(zip(columns, row)) for row in cursor.fetchall()]

    def get_last_modified(self) -> Optional[datetime]:
        """
        Get the most recent last_modified date from the enriched CVEs.

        Returns:
            The most recent last_modified datetime, or None if no CVEs exist.
        """
        with self.cursor() as (cursor, conn):
            cursor.execute(
                "SELECT MAX(last_modified) FROM cve_enriched"
            )
            result = cursor.fetchone()
            return result[0] if result and result[0] else None

    def update_epss_scores_batch(
        self,
        scores: List[Tuple[str, float, float]]
    ) -> int:
        """
        Update only EPSS scores for existing CVEs.

        Args:
            scores: List of (cve_id, epss_score, epss_percentile) tuples

        Returns:
            Number of updated rows
        """
        if not scores:
            return 0

        sql = """
            UPDATE cve_enriched
            SET epss_score = ?, epss_percentile = ?
            WHERE cve_id = ?
        """

        updated = 0
        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                # Reorder tuple: (score, percentile, cve_id) for SQL
                values = [(s[1], s[2], s[0]) for s in scores]
                cursor.executemany(sql, values)
                conn.commit()
                updated = cursor.rowcount
            except mariadb.Error as e:
                logger.error(f"Error updating EPSS scores: {e}")
                conn.rollback()
                raise
            finally:
                cursor.close()

        return updated

    def update_kev_status_batch(
        self,
        kev_data: List[Tuple[str, bool, Optional[datetime], Optional[datetime], Optional[bool]]]
    ) -> int:
        """
        Update only KEV status for existing CVEs.

        Args:
            kev_data: List of (cve_id, in_kev, date_added, due_date, ransomware_use) tuples

        Returns:
            Number of updated rows
        """
        if not kev_data:
            return 0

        sql = """
            UPDATE cve_enriched
            SET in_kev = ?, kev_date_added = ?, kev_due_date = ?, kev_ransomware_use = ?
            WHERE cve_id = ?
        """

        updated = 0
        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                # Reorder tuple for SQL: (in_kev, date_added, due_date, ransomware, cve_id)
                values = [(k[1], k[2], k[3], k[4], k[0]) for k in kev_data]
                cursor.executemany(sql, values)
                conn.commit()
                updated = cursor.rowcount
            except mariadb.Error as e:
                logger.error(f"Error updating KEV status: {e}")
                conn.rollback()
                raise
            finally:
                cursor.close()

        return updated

    def update_sigma_rules_batch(
        self,
        rules_data: List[Tuple[str, bool, int, str]]
    ) -> int:
        """
        Update detection rules for existing CVEs.

        Args:
            rules_data: List of (cve_id, has_detection_rules, detection_rules_count, detection_rules_json) tuples

        Returns:
            Number of updated rows
        """
        if not rules_data:
            return 0

        sql = """
            UPDATE cve_enriched
            SET has_detection_rules = ?, detection_rules_count = ?, detection_rules = ?
            WHERE cve_id = ?
        """

        updated = 0
        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                # Reorder tuple for SQL: (has_rules, count, json, cve_id)
                values = [(r[1], r[2], r[3], r[0]) for r in rules_data]
                cursor.executemany(sql, values)
                conn.commit()
                updated = cursor.rowcount
            except mariadb.Error as e:
                logger.error(f"Error updating Sigma rules: {e}")
                conn.rollback()
                raise
            finally:
                cursor.close()

        return updated

    def get_cves_with_detection_rules(self) -> List[str]:
        """Get all CVE IDs that have detection rules."""
        with self.cursor() as (cursor, conn):
            cursor.execute(
                "SELECT cve_id FROM cve_enriched WHERE has_detection_rules = TRUE"
            )
            return [row[0] for row in cursor.fetchall()]

    def update_nuclei_templates_batch(
        self,
        templates_data: List[Tuple[str, bool, int, str]]
    ) -> int:
        """
        Update Nuclei templates for existing CVEs.

        Args:
            templates_data: List of (cve_id, has_nuclei_template, nuclei_template_count, nuclei_templates_json) tuples

        Returns:
            Number of updated rows
        """
        if not templates_data:
            return 0

        sql = """
            UPDATE cve_enriched
            SET has_nuclei_template = ?, nuclei_template_count = ?, nuclei_templates = ?
            WHERE cve_id = ?
        """

        updated = 0
        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                # Reorder tuple for SQL: (has_template, count, json, cve_id)
                values = [(t[1], t[2], t[3], t[0]) for t in templates_data]
                cursor.executemany(sql, values)
                conn.commit()
                updated = cursor.rowcount
            except mariadb.Error as e:
                logger.error(f"Error updating Nuclei templates: {e}")
                conn.rollback()
                raise
            finally:
                cursor.close()

        return updated

    def get_cves_with_nuclei_templates(self) -> List[str]:
        """Get all CVE IDs that have Nuclei templates."""
        with self.cursor() as (cursor, conn):
            cursor.execute(
                "SELECT cve_id FROM cve_enriched WHERE has_nuclei_template = TRUE"
            )
            return [row[0] for row in cursor.fetchall()]

    def update_snort_rules_batch(
        self,
        rules_data: List[Tuple[str, bool, int, str]]
    ) -> int:
        """
        Update Snort/Suricata IDS rules for existing CVEs.

        Args:
            rules_data: List of (cve_id, has_snort_rules, snort_rules_count, snort_rules_json) tuples

        Returns:
            Number of updated rows
        """
        if not rules_data:
            return 0

        sql = """
            UPDATE cve_enriched
            SET has_snort_rules = ?, snort_rules_count = ?, snort_rules = ?
            WHERE cve_id = ?
        """

        updated = 0
        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                # Reorder tuple for SQL: (has_rules, count, json, cve_id)
                values = [(r[1], r[2], r[3], r[0]) for r in rules_data]
                cursor.executemany(sql, values)
                conn.commit()
                updated = cursor.rowcount
            except mariadb.Error as e:
                logger.error(f"Error updating Snort rules: {e}")
                conn.rollback()
                raise
            finally:
                cursor.close()

        return updated

    def get_cves_with_snort_rules(self) -> List[str]:
        """Get all CVE IDs that have Snort/Suricata IDS rules."""
        with self.cursor() as (cursor, conn):
            cursor.execute(
                "SELECT cve_id FROM cve_enriched WHERE has_snort_rules = TRUE"
            )
            return [row[0] for row in cursor.fetchall()]

    # ==================== LLM Tagging Operations ====================

    def get_untagged_cve_ids(self, limit: Optional[int] = None) -> List[str]:
        """
        Get CVE IDs that don't have LLM tags yet.

        Args:
            limit: Maximum number of CVE IDs to return

        Returns:
            List of CVE IDs without LLM tags
        """
        sql = "SELECT cve_id FROM cve_enriched WHERE llm_tagged_at IS NULL ORDER BY cve_id"
        if limit:
            sql += f" LIMIT {limit}"

        with self.cursor() as (cursor, conn):
            cursor.execute(sql)
            return [row[0] for row in cursor.fetchall()]

    def get_all_cve_ids(self) -> List[str]:
        """Get all CVE IDs in the database."""
        with self.cursor() as (cursor, conn):
            cursor.execute("SELECT cve_id FROM cve_enriched ORDER BY cve_id")
            return [row[0] for row in cursor.fetchall()]

    def update_llm_tags_batch(self, tags_data: List[Dict[str, Any]]) -> int:
        """
        Update LLM tags for multiple CVEs.

        Args:
            tags_data: List of dicts with cve_id and tag fields:
                - cve_id: str
                - llm_tags_version: str
                - llm_model_used: str
                - llm_tagged_at: datetime
                - kill_chain_phases: List[str]
                - prerequisites: List[str]
                - capabilities: List[str]
                - llm_confidence_score: float

        Returns:
            Number of updated rows
        """
        if not tags_data:
            return 0

        sql = """
            UPDATE cve_enriched SET
                llm_tags_version = ?,
                llm_model_used = ?,
                llm_tagged_at = ?,
                kill_chain_phases = ?,
                prerequisites = ?,
                capabilities = ?,
                llm_confidence_score = ?
            WHERE cve_id = ?
        """

        updated = 0
        with self.connection() as conn:
            cursor = conn.cursor()
            try:
                values = []
                for data in tags_data:
                    values.append((
                        data.get("llm_tags_version"),
                        data.get("llm_model_used"),
                        data.get("llm_tagged_at"),
                        json.dumps(data.get("kill_chain_phases", [])),
                        json.dumps(data.get("prerequisites", [])),
                        json.dumps(data.get("capabilities", [])),
                        data.get("llm_confidence_score"),
                        data.get("cve_id"),
                    ))

                cursor.executemany(sql, values)
                conn.commit()
                updated = cursor.rowcount
                logger.debug(f"Updated LLM tags for {updated} CVEs")

            except mariadb.Error as e:
                logger.error(f"Error updating LLM tags: {e}")
                conn.rollback()
                raise
            finally:
                cursor.close()

        return updated

    def get_llm_tagging_stats(self) -> Dict[str, Any]:
        """
        Get statistics about LLM tagging progress.

        Returns:
            Dict with:
                - total_cves: Total CVE count
                - tagged_cves: CVEs with LLM tags
                - untagged_cves: CVEs without LLM tags
                - avg_confidence: Average confidence score
        """
        with self.cursor() as (cursor, conn):
            cursor.execute("""
                SELECT
                    COUNT(*) as total,
                    SUM(CASE WHEN llm_tagged_at IS NOT NULL THEN 1 ELSE 0 END) as tagged,
                    AVG(llm_confidence_score) as avg_confidence
                FROM cve_enriched
            """)
            row = cursor.fetchone()

            total = row[0] or 0
            tagged = row[1] or 0

            return {
                "total_cves": total,
                "tagged_cves": tagged,
                "untagged_cves": total - tagged,
                "avg_confidence": float(row[2]) if row[2] else None,
            }

    def get_cves_by_kill_chain_phase(self, phase: str) -> List[str]:
        """
        Get CVE IDs that have a specific kill chain phase tag.

        Args:
            phase: The kill chain phase to search for

        Returns:
            List of CVE IDs with that phase
        """
        with self.cursor() as (cursor, conn):
            # Use JSON_CONTAINS to search in the JSON array
            cursor.execute(
                "SELECT cve_id FROM cve_enriched WHERE JSON_CONTAINS(kill_chain_phases, ?)",
                (json.dumps(phase),)
            )
            return [row[0] for row in cursor.fetchall()]

    def get_cves_by_capability(self, capability: str) -> List[str]:
        """
        Get CVE IDs that grant a specific capability.

        Args:
            capability: The capability to search for

        Returns:
            List of CVE IDs with that capability
        """
        with self.cursor() as (cursor, conn):
            cursor.execute(
                "SELECT cve_id FROM cve_enriched WHERE JSON_CONTAINS(capabilities, ?)",
                (json.dumps(capability),)
            )
            return [row[0] for row in cursor.fetchall()]

    def get_cves_by_prerequisite(self, prerequisite: str) -> List[str]:
        """
        Get CVE IDs that require a specific prerequisite.

        Args:
            prerequisite: The prerequisite to search for

        Returns:
            List of CVE IDs with that prerequisite
        """
        with self.cursor() as (cursor, conn):
            cursor.execute(
                "SELECT cve_id FROM cve_enriched WHERE JSON_CONTAINS(prerequisites, ?)",
                (json.dumps(prerequisite),)
            )
            return [row[0] for row in cursor.fetchall()]
