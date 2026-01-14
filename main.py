#!/usr/bin/env python3
"""
CVE Enrichment System - Main Entry Point

A comprehensive tool to enrich CVE data with:
- CWE -> CAPEC -> ATT&CK Technique -> Tactic mappings
- EPSS scores (exploit probability)
- CISA KEV status
- SigmaHQ detection rules
- Nuclei exploit templates
- Snort/Suricata IDS rules (Emerging Threats Open)

Usage:
    python main.py init                      Initialize database and download mappings
    python main.py update-mappings           Update only mapping tables
    python main.py fetch                     Bulk fetch all CVEs from NVD Feeds (fast)
    python main.py update-cve                Incremental CVE update via NVD API
    python main.py update-epss               Update EPSS scores for all CVEs
    python main.py update-kev                Update KEV status for all CVEs
    python main.py update-sigma              Update Sigma detection rules for all CVEs
    python main.py update-nuclei             Update Nuclei exploit templates for all CVEs
    python main.py update-snort              Update Snort/Suricata IDS rules for all CVEs
    python main.py update-all                Full update: CVE + EPSS + KEV + Sigma + Nuclei + Snort
    python main.py enrich-cve CVE-ID         Enrich a single CVE
    python main.py enrich-list file.txt      Enrich CVEs from a file
    python main.py show CVE-ID               Display enriched CVE data
    python main.py stats                     Show database statistics

Global flags:
    -v, --verbose                            Enable DEBUG logging
    -f, --force                              Force re-download of cached data
"""

import argparse
import logging
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent))

# Lazy imports for dependencies (checked at runtime)
def check_dependencies():
    """Check if all required dependencies are installed."""
    missing = []
    try:
        import mariadb
    except ImportError:
        missing.append("mariadb")
    try:
        import requests
    except ImportError:
        missing.append("requests")
    try:
        import lxml
    except ImportError:
        missing.append("lxml")
    try:
        import tqdm
    except ImportError:
        missing.append("tqdm")

    if missing:
        print("ERROR: Missing required dependencies:")
        print(f"  {', '.join(missing)}")
        print("\nPlease install them with:")
        print("  pip install -r requirements.txt")
        sys.exit(1)


def setup_logging(verbose: bool = False) -> None:
    """Configure logging."""
    from config import LOG_LEVEL, LOG_FORMAT, LOG_FILE

    level = logging.DEBUG if verbose else getattr(logging, LOG_LEVEL)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(logging.Formatter(LOG_FORMAT))

    # File handler
    file_handler = logging.FileHandler(LOG_FILE)
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(logging.Formatter(LOG_FORMAT))

    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(console_handler)
    root_logger.addHandler(file_handler)


def cmd_init(args: argparse.Namespace) -> int:
    """Initialize database schema and download all mappings."""
    from database import create_schema
    from enricher import CVEEnricher

    logger = logging.getLogger(__name__)
    logger.info("Initializing CVE Enrichment System...")

    try:
        # Create database schema
        logger.info("Creating database schema...")
        create_schema()

        # Download and populate mappings
        enricher = CVEEnricher()
        enricher.update_mappings(force_download=args.force)

        logger.info("Initialization complete!")
        return 0

    except Exception as e:
        logger.error(f"Initialization failed: {e}")
        return 1


def cmd_update_mappings(args: argparse.Namespace) -> int:
    """Update mapping tables only."""
    from enricher import CVEEnricher

    logger = logging.getLogger(__name__)
    logger.info("Updating mapping tables...")

    try:
        enricher = CVEEnricher()
        enricher.update_mappings(force_download=args.force)
        logger.info("Mapping tables updated successfully!")
        return 0

    except Exception as e:
        logger.error(f"Failed to update mappings: {e}")
        return 1


def cmd_fetch(args: argparse.Namespace) -> int:
    """Bulk fetch all CVEs from NVD Feeds."""
    from enricher import CVEEnricher

    logger = logging.getLogger(__name__)
    logger.info("Starting bulk CVE fetch from NVD Feeds...")

    try:
        enricher = CVEEnricher()
        count = enricher.fetch_all(
            batch_size=args.batch_size,
            force_download=args.force
        )

        logger.info(f"Fetched and enriched {count} CVEs")
        return 0

    except Exception as e:
        logger.error(f"Fetch failed: {e}")
        return 1


def cmd_update_cve(args: argparse.Namespace) -> int:
    """Incremental update via NVD API."""
    from enricher import CVEEnricher

    logger = logging.getLogger(__name__)
    logger.info("Starting incremental CVE update...")

    try:
        enricher = CVEEnricher()
        count = enricher.update(
            batch_size=args.batch_size,
            force_download=args.force
        )

        logger.info(f"Updated {count} CVEs")
        return 0

    except Exception as e:
        logger.error(f"Update failed: {e}")
        return 1


def cmd_update_epss(args: argparse.Namespace) -> int:
    """Update EPSS scores for all CVEs."""
    from enricher import CVEEnricher

    logger = logging.getLogger(__name__)
    logger.info("Starting EPSS scores update...")

    try:
        enricher = CVEEnricher()
        count = enricher.update_epss_scores(
            batch_size=args.batch_size,
            force_download=args.force
        )

        logger.info(f"Updated EPSS scores for {count} CVEs")
        return 0

    except Exception as e:
        logger.error(f"EPSS update failed: {e}")
        return 1


def cmd_update_kev(args: argparse.Namespace) -> int:
    """Update KEV status for all CVEs."""
    from enricher import CVEEnricher

    logger = logging.getLogger(__name__)
    logger.info("Starting KEV status update...")

    try:
        enricher = CVEEnricher()
        count = enricher.update_kev_status(
            batch_size=args.batch_size,
            force_download=args.force
        )

        logger.info(f"Updated KEV status for {count} CVEs")
        return 0

    except Exception as e:
        logger.error(f"KEV update failed: {e}")
        return 1


def cmd_update_sigma(args: argparse.Namespace) -> int:
    """Update Sigma detection rules for all CVEs."""
    from enricher import CVEEnricher
    from database.schema import add_detection_rules_columns

    logger = logging.getLogger(__name__)
    logger.info("Starting Sigma rules update...")

    try:
        # Ensure detection rules columns exist
        add_detection_rules_columns()

        enricher = CVEEnricher()
        count = enricher.update_sigma_rules(
            batch_size=args.batch_size,
            force_download=args.force
        )

        logger.info(f"Updated Sigma rules for {count} CVEs")
        return 0

    except Exception as e:
        logger.error(f"Sigma update failed: {e}")
        return 1


def cmd_update_nuclei(args: argparse.Namespace) -> int:
    """Update Nuclei templates for all CVEs."""
    from enricher import CVEEnricher
    from database.schema import add_nuclei_template_columns

    logger = logging.getLogger(__name__)
    logger.info("Starting Nuclei templates update...")

    try:
        # Ensure nuclei template columns exist
        add_nuclei_template_columns()

        enricher = CVEEnricher()
        count = enricher.update_nuclei_templates(
            batch_size=args.batch_size,
            force_download=args.force
        )

        logger.info(f"Updated Nuclei templates for {count} CVEs")
        return 0

    except Exception as e:
        logger.error(f"Nuclei update failed: {e}")
        return 1


def cmd_update_snort(args: argparse.Namespace) -> int:
    """Update Snort/Suricata IDS rules for all CVEs."""
    from enricher import CVEEnricher
    from database.schema import add_snort_rules_columns

    logger = logging.getLogger(__name__)
    logger.info("Starting Snort/Suricata IDS rules update...")

    try:
        # Ensure snort rules columns exist
        add_snort_rules_columns()

        enricher = CVEEnricher()
        count = enricher.update_snort_rules(
            batch_size=args.batch_size,
            force_download=args.force
        )

        logger.info(f"Updated Snort rules for {count} CVEs")
        return 0

    except Exception as e:
        logger.error(f"Snort update failed: {e}")
        return 1


def cmd_update_all(args: argparse.Namespace) -> int:
    """Update CVEs, EPSS scores, KEV status, Sigma rules, Nuclei templates, and Snort rules."""
    from enricher import CVEEnricher
    from database.schema import add_detection_rules_columns, add_nuclei_template_columns, add_snort_rules_columns

    logger = logging.getLogger(__name__)
    logger.info("Starting full update (CVE + EPSS + KEV + Sigma + Nuclei + Snort)...")

    try:
        # Ensure all columns exist
        add_detection_rules_columns()
        add_nuclei_template_columns()
        add_snort_rules_columns()

        enricher = CVEEnricher()

        # Step 1: Update CVEs from NVD
        logger.info("=== Step 1/6: Updating CVEs from NVD ===")
        cve_count = enricher.update(
            batch_size=args.batch_size,
            force_download=args.force
        )
        logger.info(f"Updated {cve_count} CVEs")

        # Step 2: Update EPSS scores
        logger.info("=== Step 2/6: Updating EPSS scores ===")
        epss_count = enricher.update_epss_scores(
            batch_size=1000,
            force_download=args.force
        )
        logger.info(f"Updated EPSS for {epss_count} CVEs")

        # Step 3: Update KEV status
        logger.info("=== Step 3/6: Updating KEV status ===")
        kev_count = enricher.update_kev_status(
            batch_size=1000,
            force_download=args.force
        )
        logger.info(f"Updated KEV for {kev_count} CVEs")

        # Step 4: Update Sigma rules
        logger.info("=== Step 4/6: Updating Sigma rules ===")
        sigma_count = enricher.update_sigma_rules(
            batch_size=1000,
            force_download=args.force
        )
        logger.info(f"Updated Sigma rules for {sigma_count} CVEs")

        # Step 5: Update Nuclei templates
        logger.info("=== Step 5/6: Updating Nuclei templates ===")
        nuclei_count = enricher.update_nuclei_templates(
            batch_size=1000,
            force_download=args.force
        )
        logger.info(f"Updated Nuclei templates for {nuclei_count} CVEs")

        # Step 6: Update Snort/Suricata IDS rules
        logger.info("=== Step 6/6: Updating Snort/ET rules ===")
        snort_count = enricher.update_snort_rules(
            batch_size=1000,
            force_download=args.force
        )
        logger.info(f"Updated Snort rules for {snort_count} CVEs")

        logger.info(
            f"Full update complete. CVEs: {cve_count}, EPSS: {epss_count}, "
            f"KEV: {kev_count}, Sigma: {sigma_count}, Nuclei: {nuclei_count}, Snort: {snort_count}"
        )
        return 0

    except Exception as e:
        logger.error(f"Update failed: {e}")
        return 1


def cmd_enrich_cve(args: argparse.Namespace) -> int:
    """Enrich a single CVE."""
    from enricher import CVEEnricher
    from database.schema import add_detection_rules_columns, add_nuclei_template_columns, add_snort_rules_columns

    logger = logging.getLogger(__name__)
    cve_id = args.cve_id.upper()

    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"

    logger.info(f"Enriching {cve_id}...")

    try:
        # Ensure all columns exist
        add_detection_rules_columns()
        add_nuclei_template_columns()
        add_snort_rules_columns()

        enricher = CVEEnricher()

        # Download EPSS, KEV, Sigma, Nuclei and Snort if needed
        enricher.epss.download()
        enricher.kev.download()
        enricher.sigma.download()
        enricher.nuclei.download()
        enricher.snort.download()

        enriched = enricher.enrich_single_cve(cve_id)

        if enriched:
            enricher.print_enriched_cve(cve_id)
            return 0
        else:
            logger.error(f"CVE {cve_id} not found")
            return 1

    except Exception as e:
        logger.error(f"Failed to enrich {cve_id}: {e}")
        return 1


def cmd_enrich_list(args: argparse.Namespace) -> int:
    """Enrich CVEs from a file."""
    from enricher import CVEEnricher
    from database.schema import add_detection_rules_columns, add_nuclei_template_columns, add_snort_rules_columns

    logger = logging.getLogger(__name__)
    file_path = Path(args.file)

    if not file_path.exists():
        logger.error(f"File not found: {file_path}")
        return 1

    try:
        # Ensure all columns exist
        add_detection_rules_columns()
        add_nuclei_template_columns()
        add_snort_rules_columns()

        # Read CVE IDs from file
        with open(file_path, "r") as f:
            cve_ids = []
            for line in f:
                cve_id = line.strip().upper()
                if cve_id and not cve_id.startswith("#"):
                    if not cve_id.startswith("CVE-"):
                        cve_id = f"CVE-{cve_id}"
                    cve_ids.append(cve_id)

        if not cve_ids:
            logger.error("No CVE IDs found in file")
            return 1

        logger.info(f"Found {len(cve_ids)} CVE IDs in file")

        enricher = CVEEnricher()

        # Download EPSS, KEV, Sigma, Nuclei and Snort if needed
        enricher.epss.download(force=args.force)
        enricher.kev.download(force=args.force)
        enricher.sigma.download(force=args.force)
        enricher.nuclei.download(force=args.force)
        enricher.snort.download(force=args.force)

        count = enricher.enrich_cve_list(cve_ids, batch_size=args.batch_size)

        logger.info(f"Successfully enriched {count}/{len(cve_ids)} CVEs")
        return 0 if count > 0 else 1

    except Exception as e:
        logger.error(f"Failed to enrich CVEs from file: {e}")
        return 1


def cmd_show(args: argparse.Namespace) -> int:
    """Display enriched CVE data."""
    from enricher import CVEEnricher

    cve_id = args.cve_id.upper()

    if not cve_id.startswith("CVE-"):
        cve_id = f"CVE-{cve_id}"

    try:
        enricher = CVEEnricher()
        enricher.print_enriched_cve(cve_id)
        return 0

    except Exception as e:
        logging.error(f"Failed to show {cve_id}: {e}")
        return 1


def cmd_stats(args: argparse.Namespace) -> int:
    """Show database statistics."""
    from enricher import CVEEnricher

    try:
        enricher = CVEEnricher()
        stats = enricher.get_enrichment_stats()

        print("\n=== CVE Enrichment Database Statistics ===\n")
        print(f"Total Enriched CVEs: {stats.get('total_cves', 0):,}")
        print(f"CVEs in KEV: {stats.get('kev_cves', 0):,}")
        print(f"\nMapping Tables:")
        print(f"  CWE Entries: {stats.get('cwe_count', 0):,}")
        print(f"  CWE->CAPEC Mappings: {stats.get('cwe_capec_mappings', 0):,}")
        print(f"  CAPEC->Technique Mappings: {stats.get('capec_technique_mappings', 0):,}")
        print(f"  Technique->Tactic Mappings: {stats.get('technique_tactic_mappings', 0):,}")
        print(f"\nDetection & Exploit Templates:")
        print(f"  CVEs with Sigma rules: {stats.get('cves_with_detection_rules', 0):,}")
        print(f"  CVEs with Nuclei templates: {stats.get('cves_with_nuclei_templates', 0):,}")
        print(f"  CVEs with Snort/ET rules: {stats.get('cves_with_snort_rules', 0):,}")
        print()

        return 0

    except Exception as e:
        logging.error(f"Failed to get stats: {e}")
        return 1


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="CVE Enrichment System",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )

    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose (DEBUG) logging"
    )

    parser.add_argument(
        "-f", "--force",
        action="store_true",
        help="Force re-download of cached data"
    )

    # Subcommands
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # Init command
    init_parser = subparsers.add_parser(
        "init",
        aliases=["--init"],
        help="Initialize database and download mappings"
    )
    init_parser.set_defaults(func=cmd_init)

    # Update mappings command
    update_mappings_parser = subparsers.add_parser(
        "update-mappings",
        aliases=["--update-mappings"],
        help="Update mapping tables only"
    )
    update_mappings_parser.set_defaults(func=cmd_update_mappings)

    # Fetch command (bulk download from feeds)
    fetch_parser = subparsers.add_parser(
        "fetch",
        aliases=["--fetch"],
        help="Bulk fetch all CVEs from NVD Feeds (fast initial population)"
    )
    fetch_parser.add_argument(
        "--batch-size",
        type=int,
        default=500,
        help="Batch size for database inserts (default: 500)"
    )
    fetch_parser.set_defaults(func=cmd_fetch)

    # Update CVE command (incremental via API)
    update_cve_parser = subparsers.add_parser(
        "update-cve",
        aliases=["--update-cve"],
        help="Incremental CVE update via NVD API (based on last modified date)"
    )
    update_cve_parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Batch size for database inserts (default: 100)"
    )
    update_cve_parser.set_defaults(func=cmd_update_cve)

    # Update EPSS command
    update_epss_parser = subparsers.add_parser(
        "update-epss",
        aliases=["--update-epss"],
        help="Update EPSS scores for all CVEs in database"
    )
    update_epss_parser.add_argument(
        "--batch-size",
        type=int,
        default=1000,
        help="Batch size for database updates (default: 1000)"
    )
    update_epss_parser.set_defaults(func=cmd_update_epss)

    # Update KEV command
    update_kev_parser = subparsers.add_parser(
        "update-kev",
        aliases=["--update-kev"],
        help="Update KEV status for all CVEs in database"
    )
    update_kev_parser.add_argument(
        "--batch-size",
        type=int,
        default=1000,
        help="Batch size for database updates (default: 1000)"
    )
    update_kev_parser.set_defaults(func=cmd_update_kev)

    # Update Sigma command
    update_sigma_parser = subparsers.add_parser(
        "update-sigma",
        aliases=["--update-sigma"],
        help="Update Sigma detection rules for all CVEs in database"
    )
    update_sigma_parser.add_argument(
        "--batch-size",
        type=int,
        default=1000,
        help="Batch size for database updates (default: 1000)"
    )
    update_sigma_parser.set_defaults(func=cmd_update_sigma)

    # Update Nuclei command
    update_nuclei_parser = subparsers.add_parser(
        "update-nuclei",
        aliases=["--update-nuclei"],
        help="Update Nuclei exploit templates for all CVEs in database"
    )
    update_nuclei_parser.add_argument(
        "--batch-size",
        type=int,
        default=1000,
        help="Batch size for database updates (default: 1000)"
    )
    update_nuclei_parser.set_defaults(func=cmd_update_nuclei)

    # Update Snort command
    update_snort_parser = subparsers.add_parser(
        "update-snort",
        aliases=["--update-snort"],
        help="Update Snort/Suricata IDS rules for all CVEs in database"
    )
    update_snort_parser.add_argument(
        "--batch-size",
        type=int,
        default=1000,
        help="Batch size for database updates (default: 1000)"
    )
    update_snort_parser.set_defaults(func=cmd_update_snort)

    # Update all command (CVE + EPSS + KEV + Sigma + Nuclei + Snort)
    update_all_parser = subparsers.add_parser(
        "update-all",
        aliases=["--update-all"],
        help="Full update: CVEs from NVD + EPSS scores + KEV status + Sigma rules + Nuclei templates + Snort rules"
    )
    update_all_parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Batch size for CVE updates (default: 100)"
    )
    update_all_parser.set_defaults(func=cmd_update_all)

    # Enrich single CVE command
    enrich_cve_parser = subparsers.add_parser(
        "enrich-cve",
        aliases=["--enrich-cve"],
        help="Enrich a single CVE"
    )
    enrich_cve_parser.add_argument(
        "cve_id",
        help="CVE identifier (e.g., CVE-2021-44228)"
    )
    enrich_cve_parser.set_defaults(func=cmd_enrich_cve)

    # Enrich from list command
    enrich_list_parser = subparsers.add_parser(
        "enrich-list",
        aliases=["--enrich-list"],
        help="Enrich CVEs from a file"
    )
    enrich_list_parser.add_argument(
        "file",
        help="File containing CVE IDs (one per line)"
    )
    enrich_list_parser.add_argument(
        "--batch-size",
        type=int,
        default=100,
        help="Batch size for database inserts (default: 100)"
    )
    enrich_list_parser.set_defaults(func=cmd_enrich_list)

    # Show command
    show_parser = subparsers.add_parser(
        "show",
        aliases=["--show"],
        help="Display enriched CVE data"
    )
    show_parser.add_argument(
        "cve_id",
        help="CVE identifier to display"
    )
    show_parser.set_defaults(func=cmd_show)

    # Stats command
    stats_parser = subparsers.add_parser(
        "stats",
        aliases=["--stats"],
        help="Show database statistics"
    )
    stats_parser.set_defaults(func=cmd_stats)

    args = parser.parse_args()

    # Setup logging
    setup_logging(args.verbose)

    # Handle legacy --flag style commands
    if args.command is None:
        # Check sys.argv for legacy flags
        for arg in sys.argv[1:]:
            if arg == "--init":
                args.command = "init"
                args.func = cmd_init
                break
            elif arg == "--update-mappings":
                args.command = "update-mappings"
                args.func = cmd_update_mappings
                break
            elif arg == "--fetch":
                args.command = "fetch"
                args.func = cmd_fetch
                args.batch_size = 500
                break
            elif arg == "--update-cve":
                args.command = "update-cve"
                args.func = cmd_update_cve
                args.batch_size = 100
                break
            elif arg == "--update-epss":
                args.command = "update-epss"
                args.func = cmd_update_epss
                args.batch_size = 1000
                break
            elif arg == "--update-kev":
                args.command = "update-kev"
                args.func = cmd_update_kev
                args.batch_size = 1000
                break
            elif arg == "--update-sigma":
                args.command = "update-sigma"
                args.func = cmd_update_sigma
                args.batch_size = 1000
                break
            elif arg == "--update-nuclei":
                args.command = "update-nuclei"
                args.func = cmd_update_nuclei
                args.batch_size = 1000
                break
            elif arg == "--update-snort":
                args.command = "update-snort"
                args.func = cmd_update_snort
                args.batch_size = 1000
                break
            elif arg == "--update-all":
                args.command = "update-all"
                args.func = cmd_update_all
                args.batch_size = 100
                break
            elif arg.startswith("--enrich-cve"):
                args.command = "enrich-cve"
                args.func = cmd_enrich_cve
                # Get the CVE ID from next argument
                idx = sys.argv.index(arg)
                if idx + 1 < len(sys.argv):
                    args.cve_id = sys.argv[idx + 1]
                break
            elif arg.startswith("--enrich-list"):
                args.command = "enrich-list"
                args.func = cmd_enrich_list
                args.batch_size = 100
                # Get the file from next argument
                idx = sys.argv.index(arg)
                if idx + 1 < len(sys.argv):
                    args.file = sys.argv[idx + 1]
                break
            elif arg == "--stats":
                args.command = "stats"
                args.func = cmd_stats
                break

    if args.command is None or not hasattr(args, 'func'):
        parser.print_help()
        return 1

    # Check dependencies before executing command
    check_dependencies()

    # Execute command
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
