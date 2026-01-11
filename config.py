"""
Configuration module for CVE Enrichment System.
Uses environment variables or .env file for sensitive settings.
"""

import os
from pathlib import Path

# Load .env file if python-dotenv is available
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass  # dotenv not installed, use environment variables directly

# Base paths
BASE_DIR = Path(__file__).parent
CACHE_DIR = BASE_DIR / "cache"
CACHE_DIR.mkdir(exist_ok=True)

# Database configuration
DB_CONFIG = {
    "host": os.getenv("DB_HOST", "localhost"),
    "port": int(os.getenv("DB_PORT", 3306)),
    "user": os.getenv("DB_USER", "root"),
    "password": os.getenv("DB_PASSWORD", ""),
    "database": os.getenv("DB_NAME", "cve_enrichment"),
}

# NVD API configuration
NVD_API_KEY = os.getenv("NVD_API_KEY", None)
NVD_BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_RATE_LIMIT = 50 if NVD_API_KEY else 5  # requests per 30 seconds
NVD_RATE_WINDOW = 30  # seconds

# External data sources
DATA_SOURCES = {
    "cwe": {
        "url": "https://cwe.mitre.org/data/xml/cwec_latest.xml.zip",
        "cache_file": CACHE_DIR / "cwec_latest.xml.zip",
        "extracted_file": CACHE_DIR / "cwec_latest.xml",
    },
    "capec": {
        "url": "https://capec.mitre.org/data/xml/capec_latest.xml",
        "cache_file": CACHE_DIR / "capec_latest.xml",
    },
    "attack": {
        "url": "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json",
        "cache_file": CACHE_DIR / "enterprise-attack.json",
    },
    "epss": {
        "url": "https://api.first.org/data/v1/epss",
        "cache_file": CACHE_DIR / "epss_scores.json",
    },
    "kev": {
        "url": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        "cache_file": CACHE_DIR / "kev.json",
    },
    "sigma": {
        "url": "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip",
        "cache_file": CACHE_DIR / "sigma-master.zip",
        "extracted_dir": CACHE_DIR / "sigma-master",
    },
}

# Cache settings
CACHE_EXPIRY_HOURS = 24  # Re-download if cache is older than this

# Logging configuration
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")
LOG_FORMAT = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
LOG_FILE = BASE_DIR / "cve_enrichment.log"

# Retry configuration
MAX_RETRIES = 5
INITIAL_BACKOFF = 1  # seconds
MAX_BACKOFF = 60  # seconds

# SSL configuration (for corporate environments with custom CA or proxy)
# SSL_VERIFY: True (default), False (disable verification), or path to CA bundle
_ssl_verify_env = os.getenv("SSL_VERIFY", "true").lower()
if _ssl_verify_env == "false":
    SSL_VERIFY = False
elif _ssl_verify_env == "true":
    SSL_VERIFY = True
else:
    # Assume it's a path to a CA bundle
    SSL_VERIFY = _ssl_verify_env

# Alternative: specify CA cert file directly (overrides SSL_VERIFY if set)
SSL_CERT_FILE = os.getenv("SSL_CERT_FILE", None)
if SSL_CERT_FILE:
    SSL_VERIFY = SSL_CERT_FILE
