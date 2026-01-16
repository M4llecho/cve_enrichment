"""
Database schema creation and management.
"""

import logging
import mariadb
from typing import Optional

from config import DB_CONFIG

logger = logging.getLogger(__name__)

# SQL statements for creating tables
CREATE_MAP_CWE_CAPEC = """
CREATE TABLE IF NOT EXISTS map_cwe_capec (
    cwe_id VARCHAR(20) NOT NULL,
    capec_id VARCHAR(20) NOT NULL,
    PRIMARY KEY (cwe_id, capec_id),
    INDEX idx_cwe_id (cwe_id),
    INDEX idx_capec_id (capec_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
"""

CREATE_MAP_CAPEC_TECHNIQUE = """
CREATE TABLE IF NOT EXISTS map_capec_technique (
    capec_id VARCHAR(20) NOT NULL,
    technique_id VARCHAR(20) NOT NULL,
    technique_name VARCHAR(255),
    PRIMARY KEY (capec_id, technique_id),
    INDEX idx_capec_id (capec_id),
    INDEX idx_technique_id (technique_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
"""

CREATE_MAP_TECHNIQUE_TACTIC = """
CREATE TABLE IF NOT EXISTS map_technique_tactic (
    technique_id VARCHAR(20) NOT NULL,
    tactic_id VARCHAR(50) NOT NULL,
    tactic_name VARCHAR(100),
    PRIMARY KEY (technique_id, tactic_id),
    INDEX idx_technique_id (technique_id),
    INDEX idx_tactic_id (tactic_id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
"""

CREATE_CVE_ENRICHED = """
CREATE TABLE IF NOT EXISTS cve_enriched (
    cve_id VARCHAR(20) PRIMARY KEY,
    description TEXT,
    published_date DATETIME,
    last_modified DATETIME,

    -- CVSS (supports 4.0, 3.1, 3.0, 2.0)
    cvss_score DECIMAL(3,1),
    cvss_vector VARCHAR(200),
    cvss_severity VARCHAR(20),
    cvss_version VARCHAR(10),

    -- Vulnerability status (Analyzed, Modified, Rejected, etc.)
    vuln_status VARCHAR(50),

    -- CWE (supports multiple CWEs per CVE)
    cwe_ids JSON,
    cwe_names JSON,

    -- CAPEC (JSON array)
    capec_ids JSON,

    -- ATT&CK (JSON arrays)
    technique_ids JSON,
    technique_names JSON,
    tactic_ids JSON,
    tactic_names JSON,

    -- EPSS
    epss_score DECIMAL(5,4),
    epss_percentile DECIMAL(5,4),

    -- KEV
    in_kev BOOLEAN DEFAULT FALSE,
    kev_date_added DATE,
    kev_due_date DATE,
    kev_ransomware_use BOOLEAN,

    -- Exploit/Patch info (from NVD references)
    has_exploit BOOLEAN DEFAULT FALSE,
    exploit_count INT DEFAULT 0,
    has_patch BOOLEAN DEFAULT FALSE,
    reference_count INT DEFAULT 0,

    -- Affected Products (extracted from CPE)
    affected_vendors JSON,
    affected_products JSON,
    affected_products_detail JSON,

    -- Detection Rules (Sigma)
    has_detection_rules BOOLEAN DEFAULT FALSE,
    detection_rules_count INT DEFAULT 0,
    detection_rules JSON,

    -- Exploit Templates (Nuclei)
    has_nuclei_template BOOLEAN DEFAULT FALSE,
    nuclei_template_count INT DEFAULT 0,
    nuclei_templates JSON,

    -- Metadata
    last_enriched_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

    INDEX idx_cvss_score (cvss_score),
    INDEX idx_cvss_version (cvss_version),
    INDEX idx_vuln_status (vuln_status),
    INDEX idx_epss_score (epss_score),
    INDEX idx_in_kev (in_kev),
    INDEX idx_has_exploit (has_exploit),
    INDEX idx_has_detection_rules (has_detection_rules),
    INDEX idx_has_nuclei_template (has_nuclei_template),
    INDEX idx_published (published_date)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
"""

CREATE_CWE_DETAILS = """
CREATE TABLE IF NOT EXISTS cwe_details (
    cwe_id VARCHAR(20) PRIMARY KEY,
    cwe_name VARCHAR(255),
    description TEXT,
    INDEX idx_cwe_name (cwe_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;
"""

ALL_TABLES = [
    ("map_cwe_capec", CREATE_MAP_CWE_CAPEC),
    ("map_capec_technique", CREATE_MAP_CAPEC_TECHNIQUE),
    ("map_technique_tactic", CREATE_MAP_TECHNIQUE_TACTIC),
    ("cwe_details", CREATE_CWE_DETAILS),
    ("cve_enriched", CREATE_CVE_ENRICHED),
]


def get_connection() -> mariadb.Connection:
    """Get a database connection."""
    try:
        conn = mariadb.connect(
            host=DB_CONFIG["host"],
            port=DB_CONFIG["port"],
            user=DB_CONFIG["user"],
            password=DB_CONFIG["password"],
        )
        return conn
    except mariadb.Error as e:
        logger.error(f"Error connecting to MariaDB: {e}")
        raise


def get_db_connection() -> mariadb.Connection:
    """Get a database connection with database selected."""
    try:
        conn = mariadb.connect(
            host=DB_CONFIG["host"],
            port=DB_CONFIG["port"],
            user=DB_CONFIG["user"],
            password=DB_CONFIG["password"],
            database=DB_CONFIG["database"],
        )
        return conn
    except mariadb.Error as e:
        logger.error(f"Error connecting to MariaDB database: {e}")
        raise


def create_database() -> None:
    """Create the database if it doesn't exist."""
    conn = get_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            f"CREATE DATABASE IF NOT EXISTS {DB_CONFIG['database']} "
            "CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci"
        )
        conn.commit()
        logger.info(f"Database '{DB_CONFIG['database']}' created or already exists")
    except mariadb.Error as e:
        logger.error(f"Error creating database: {e}")
        raise
    finally:
        cursor.close()
        conn.close()


def create_schema() -> None:
    """Create all required tables."""
    create_database()
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        for table_name, create_sql in ALL_TABLES:
            logger.info(f"Creating table: {table_name}")
            cursor.execute(create_sql)
        conn.commit()
        logger.info("All tables created successfully")
    except mariadb.Error as e:
        logger.error(f"Error creating tables: {e}")
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()


def drop_schema(confirm: bool = False) -> None:
    """Drop all tables (use with caution)."""
    if not confirm:
        logger.warning("Drop schema called without confirmation. Skipping.")
        return

    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Drop in reverse order due to potential dependencies
        for table_name, _ in reversed(ALL_TABLES):
            logger.warning(f"Dropping table: {table_name}")
            cursor.execute(f"DROP TABLE IF EXISTS {table_name}")
        conn.commit()
        logger.info("All tables dropped successfully")
    except mariadb.Error as e:
        logger.error(f"Error dropping tables: {e}")
        conn.rollback()
        raise
    finally:
        cursor.close()
        conn.close()


def table_exists(table_name: str) -> bool:
    """Check if a table exists in the database."""
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(
            "SELECT COUNT(*) FROM information_schema.tables "
            "WHERE table_schema = ? AND table_name = ?",
            (DB_CONFIG["database"], table_name)
        )
        result = cursor.fetchone()
        return result[0] > 0 if result else False
    except mariadb.Error as e:
        logger.error(f"Error checking table existence: {e}")
        return False
    finally:
        cursor.close()
        conn.close()


def get_table_count(table_name: str) -> int:
    """Get the number of rows in a table."""
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        cursor.execute(f"SELECT COUNT(*) FROM {table_name}")
        result = cursor.fetchone()
        return result[0] if result else 0
    except mariadb.Error as e:
        logger.error(f"Error getting table count: {e}")
        return 0
    finally:
        cursor.close()
        conn.close()


def add_detection_rules_columns() -> bool:
    """
    Add detection rules columns to existing cve_enriched table.

    This migration adds the Sigma detection rules fields if they don't exist.
    Safe to run multiple times.

    Returns:
        True if successful, False otherwise
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Check if columns already exist
        cursor.execute(
            "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
            "WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'cve_enriched' "
            "AND COLUMN_NAME = 'has_detection_rules'",
            (DB_CONFIG["database"],)
        )

        if cursor.fetchone():
            logger.info("Detection rules columns already exist")
            return True

        # Add new columns
        logger.info("Adding detection rules columns to cve_enriched table...")

        alter_statements = [
            "ALTER TABLE cve_enriched ADD COLUMN has_detection_rules BOOLEAN DEFAULT FALSE",
            "ALTER TABLE cve_enriched ADD COLUMN detection_rules_count INT DEFAULT 0",
            "ALTER TABLE cve_enriched ADD COLUMN detection_rules JSON",
            "ALTER TABLE cve_enriched ADD INDEX idx_has_detection_rules (has_detection_rules)",
        ]

        for stmt in alter_statements:
            try:
                cursor.execute(stmt)
            except mariadb.Error as e:
                # Ignore "duplicate column" or "duplicate key" errors
                if "Duplicate" not in str(e):
                    raise

        conn.commit()
        logger.info("Detection rules columns added successfully")
        return True

    except mariadb.Error as e:
        logger.error(f"Error adding detection rules columns: {e}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()


def add_nuclei_template_columns() -> bool:
    """
    Add Nuclei template columns to existing cve_enriched table.

    This migration adds the Nuclei template fields if they don't exist.
    Safe to run multiple times.

    Returns:
        True if successful, False otherwise
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Check if columns already exist
        cursor.execute(
            "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
            "WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'cve_enriched' "
            "AND COLUMN_NAME = 'has_nuclei_template'",
            (DB_CONFIG["database"],)
        )

        if cursor.fetchone():
            logger.info("Nuclei template columns already exist")
            return True

        # Add new columns
        logger.info("Adding Nuclei template columns to cve_enriched table...")

        alter_statements = [
            "ALTER TABLE cve_enriched ADD COLUMN has_nuclei_template BOOLEAN DEFAULT FALSE",
            "ALTER TABLE cve_enriched ADD COLUMN nuclei_template_count INT DEFAULT 0",
            "ALTER TABLE cve_enriched ADD COLUMN nuclei_templates JSON",
            "ALTER TABLE cve_enriched ADD INDEX idx_has_nuclei_template (has_nuclei_template)",
        ]

        for stmt in alter_statements:
            try:
                cursor.execute(stmt)
            except mariadb.Error as e:
                # Ignore "duplicate column" or "duplicate key" errors
                if "Duplicate" not in str(e):
                    raise

        conn.commit()
        logger.info("Nuclei template columns added successfully")
        return True

    except mariadb.Error as e:
        logger.error(f"Error adding Nuclei template columns: {e}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()


def migrate_cpe_to_affected_products() -> bool:
    """
    Migrate from cpe column to affected_vendors/products/detail columns.

    This migration:
    1. Adds the 3 new affected_* columns if they don't exist
    2. Drops the old cpe column if it exists

    Safe to run multiple times.

    Returns:
        True if successful, False otherwise
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Check if new columns already exist
        cursor.execute(
            "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
            "WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'cve_enriched' "
            "AND COLUMN_NAME = 'affected_vendors'",
            (DB_CONFIG["database"],)
        )
        new_columns_exist = cursor.fetchone() is not None

        # Check if old cpe column exists
        cursor.execute(
            "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
            "WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'cve_enriched' "
            "AND COLUMN_NAME = 'cpe'",
            (DB_CONFIG["database"],)
        )
        old_column_exists = cursor.fetchone() is not None

        if new_columns_exist and not old_column_exists:
            logger.info("CPE migration already complete")
            return True

        # Add new columns if they don't exist
        if not new_columns_exist:
            logger.info("Adding affected_* columns to cve_enriched table...")

            add_statements = [
                "ALTER TABLE cve_enriched ADD COLUMN affected_vendors JSON",
                "ALTER TABLE cve_enriched ADD COLUMN affected_products JSON",
                "ALTER TABLE cve_enriched ADD COLUMN affected_products_detail JSON",
            ]

            for stmt in add_statements:
                try:
                    cursor.execute(stmt)
                except mariadb.Error as e:
                    if "Duplicate" not in str(e):
                        raise

            logger.info("Affected products columns added")

        # Drop old cpe column if it exists
        if old_column_exists:
            logger.info("Dropping old cpe column...")
            cursor.execute("ALTER TABLE cve_enriched DROP COLUMN cpe")
            logger.info("Old cpe column dropped")

        conn.commit()
        logger.info("CPE to affected products migration completed successfully")
        return True

    except mariadb.Error as e:
        logger.error(f"Error during CPE migration: {e}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()


def add_snort_rules_columns() -> bool:
    """
    Add Snort/Suricata IDS rules columns to existing cve_enriched table.

    This migration adds the Snort rules fields if they don't exist.
    Safe to run multiple times.

    Returns:
        True if successful, False otherwise
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Check if columns already exist
        cursor.execute(
            "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
            "WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'cve_enriched' "
            "AND COLUMN_NAME = 'has_snort_rules'",
            (DB_CONFIG["database"],)
        )

        if cursor.fetchone():
            logger.info("Snort rules columns already exist")
            return True

        # Add new columns
        logger.info("Adding Snort rules columns to cve_enriched table...")

        alter_statements = [
            "ALTER TABLE cve_enriched ADD COLUMN has_snort_rules BOOLEAN DEFAULT FALSE",
            "ALTER TABLE cve_enriched ADD COLUMN snort_rules_count INT DEFAULT 0",
            "ALTER TABLE cve_enriched ADD COLUMN snort_rules JSON",
            "ALTER TABLE cve_enriched ADD INDEX idx_has_snort_rules (has_snort_rules)",
        ]

        for stmt in alter_statements:
            try:
                cursor.execute(stmt)
            except mariadb.Error as e:
                # Ignore "duplicate column" or "duplicate key" errors
                if "Duplicate" not in str(e):
                    raise

        conn.commit()
        logger.info("Snort rules columns added successfully")
        return True

    except mariadb.Error as e:
        logger.error(f"Error adding Snort rules columns: {e}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()


def add_llm_tagging_columns() -> bool:
    """
    Add LLM tagging columns to existing cve_enriched table.

    This migration adds columns for LLM-generated security tags used for
    kill chain reconstruction. Safe to run multiple times.

    Columns added:
    - llm_tags_version: Version of the taxonomy used
    - llm_model_used: Which LLM model generated the tags
    - llm_tagged_at: When the tags were generated
    - kill_chain_phases: JSON array of kill chain phase tags
    - prerequisites: JSON array of prerequisite tags (input for chaining)
    - capabilities: JSON array of capability tags (output for chaining)
    - llm_confidence_score: Confidence score from the model

    Returns:
        True if successful, False otherwise
    """
    conn = get_db_connection()
    cursor = conn.cursor()

    try:
        # Check if columns already exist
        cursor.execute(
            "SELECT COLUMN_NAME FROM information_schema.COLUMNS "
            "WHERE TABLE_SCHEMA = ? AND TABLE_NAME = 'cve_enriched' "
            "AND COLUMN_NAME = 'llm_tagged_at'",
            (DB_CONFIG["database"],)
        )

        if cursor.fetchone():
            logger.info("LLM tagging columns already exist")
            return True

        # Add new columns
        logger.info("Adding LLM tagging columns to cve_enriched table...")

        alter_statements = [
            # Metadata
            "ALTER TABLE cve_enriched ADD COLUMN llm_tags_version VARCHAR(20)",
            "ALTER TABLE cve_enriched ADD COLUMN llm_model_used VARCHAR(100)",
            "ALTER TABLE cve_enriched ADD COLUMN llm_tagged_at DATETIME",
            # Tag categories (JSON arrays)
            "ALTER TABLE cve_enriched ADD COLUMN kill_chain_phases JSON",
            "ALTER TABLE cve_enriched ADD COLUMN prerequisites JSON",
            "ALTER TABLE cve_enriched ADD COLUMN capabilities JSON",
            # Quality metrics
            "ALTER TABLE cve_enriched ADD COLUMN llm_confidence_score DECIMAL(3,2)",
            # Index for finding untagged CVEs
            "ALTER TABLE cve_enriched ADD INDEX idx_llm_tagged_at (llm_tagged_at)",
        ]

        for stmt in alter_statements:
            try:
                cursor.execute(stmt)
            except mariadb.Error as e:
                # Ignore "duplicate column" or "duplicate key" errors
                if "Duplicate" not in str(e):
                    raise

        conn.commit()
        logger.info("LLM tagging columns added successfully")
        return True

    except mariadb.Error as e:
        logger.error(f"Error adding LLM tagging columns: {e}")
        conn.rollback()
        return False
    finally:
        cursor.close()
        conn.close()
