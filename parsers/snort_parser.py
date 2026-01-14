"""
Snort/Suricata rules parser - extracts CVE references from IDS/IPS rules.
"""

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Pattern to extract CVE from reference:cve,YYYY-NNNNN
CVE_REFERENCE_PATTERN = re.compile(
    r'reference\s*:\s*cve\s*,\s*(\d{4}-\d+)',
    re.IGNORECASE
)

# Pattern to extract SID
SID_PATTERN = re.compile(r'sid\s*:\s*(\d+)\s*;', re.IGNORECASE)

# Pattern to extract REV
REV_PATTERN = re.compile(r'rev\s*:\s*(\d+)\s*;', re.IGNORECASE)

# Pattern to extract MSG (description)
MSG_PATTERN = re.compile(r'msg\s*:\s*"([^"]+)"\s*;', re.IGNORECASE)

# Pattern to extract CLASSTYPE
CLASSTYPE_PATTERN = re.compile(r'classtype\s*:\s*([a-z0-9_-]+)\s*;', re.IGNORECASE)

# Mapping classtype -> severity
CLASSTYPE_SEVERITY = {
    # Critical
    "successful-admin": "critical",
    "successful-recon-largescale": "critical",
    # High
    "attempted-admin": "high",
    "attempted-user": "high",
    "shellcode-detect": "high",
    "successful-user": "high",
    "trojan-activity": "high",
    "web-application-attack": "high",
    "exploit-kit": "high",
    # Medium
    "unsuccessful-user": "medium",
    "attempted-dos": "medium",
    "bad-unknown": "medium",
    "default-login-attempt": "medium",
    "denial-of-service": "medium",
    "misc-attack": "medium",
    "suspicious-filename-detect": "medium",
    "suspicious-login": "medium",
    "system-call-detect": "medium",
    "web-application-activity": "medium",
    # Low
    "attempted-recon": "low",
    "misc-activity": "low",
    "network-scan": "low",
    "policy-violation": "low",
    "protocol-command-decode": "low",
    "rpc-portmap-decode": "low",
    "string-detect": "low",
    "unusual-client-port-connection": "low",
    # Info
    "not-suspicious": "info",
    "unknown": "info",
}

# Rule files relevant for CVE extraction
RELEVANT_RULE_FILES = [
    "emerging-exploit.rules",
    "emerging-web_server.rules",
    "emerging-web_client.rules",
    "emerging-web_specific_apps.rules",
    "emerging-malware.rules",
    "emerging-scada.rules",
    "emerging-attack_response.rules",
    "emerging-sql.rules",
    "emerging-shellcode.rules",
    "emerging-worm.rules",
    "emerging-trojan.rules",
]


class SnortParser:
    """Parser for Snort/Suricata IDS rules to extract CVE mappings."""

    def __init__(self, base_dir: Path):
        """
        Initialize the Snort parser.

        Args:
            base_dir: Path to the extracted ET Open rules directory
        """
        self.base_dir = Path(base_dir)
        self._cve_index: Optional[Dict[str, List[Dict[str, Any]]]] = None

    def _extract_cve_ids(self, rule_line: str) -> List[str]:
        """Extract all CVE IDs from a rule line."""
        cve_ids = []
        for match in CVE_REFERENCE_PATTERN.finditer(rule_line):
            cve_id = f"CVE-{match.group(1)}"
            if cve_id not in cve_ids:
                cve_ids.append(cve_id)
        return cve_ids

    def _parse_rule_line(self, rule_line: str, filename: str) -> Optional[Dict[str, Any]]:
        """
        Parse a single rule line.

        Returns rule info if it contains CVE references, None otherwise.
        """
        # Skip comments and empty lines
        rule_line = rule_line.strip()
        if not rule_line or rule_line.startswith('#'):
            return None

        # Extract CVE references
        cve_ids = self._extract_cve_ids(rule_line)
        if not cve_ids:
            return None

        # Extract SID
        sid_match = SID_PATTERN.search(rule_line)
        sid = sid_match.group(1) if sid_match else None

        # Extract MSG (description)
        msg_match = MSG_PATTERN.search(rule_line)
        msg = msg_match.group(1) if msg_match else "Unknown"

        # Extract CLASSTYPE
        classtype_match = CLASSTYPE_PATTERN.search(rule_line)
        classtype = classtype_match.group(1) if classtype_match else "unknown"

        # Map classtype to severity
        severity = CLASSTYPE_SEVERITY.get(classtype, "info")

        return {
            'sid': sid,
            'msg': msg,
            'classtype': classtype,
            'severity': severity,
            'filename': filename,
            'cve_ids': cve_ids,
        }

    def _parse_rules_file(self, file_path: Path) -> List[Dict[str, Any]]:
        """Parse a .rules file and extract CVE-related rules."""
        rules = []
        filename = file_path.name

        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    rule_info = self._parse_rule_line(line, filename)
                    if rule_info:
                        rules.append(rule_info)
        except Exception as e:
            logger.debug(f"Error parsing {file_path}: {e}")

        return rules

    def build_cve_index(self, force_rebuild: bool = False) -> Dict[str, List[Dict[str, Any]]]:
        """
        Build an index mapping CVE IDs to their associated IDS rules.

        Args:
            force_rebuild: If True, rebuild the index even if it already exists

        Returns:
            Dictionary mapping CVE IDs to lists of rule info
        """
        if self._cve_index is not None and not force_rebuild:
            return self._cve_index

        logger.info("Building Snort/ET Open CVE index...")

        cve_index: Dict[str, List[Dict[str, Any]]] = {}
        rules_with_cve = 0

        if not self.base_dir.exists():
            logger.error(f"Rules directory does not exist: {self.base_dir}")
            self._cve_index = {}
            return self._cve_index

        # Parse relevant .rules files
        for rule_filename in RELEVANT_RULE_FILES:
            rule_path = self.base_dir / rule_filename
            if not rule_path.exists():
                logger.debug(f"Rule file not found: {rule_path}")
                continue

            rules = self._parse_rules_file(rule_path)
            rules_with_cve += len(rules)

            for rule_info in rules:
                for cve_id in rule_info['cve_ids']:
                    if cve_id not in cve_index:
                        cve_index[cve_id] = []

                    # Create entry without cve_ids (to avoid redundancy)
                    entry = {
                        'sid': rule_info['sid'],
                        'msg': rule_info['msg'],
                        'classtype': rule_info['classtype'],
                        'severity': rule_info['severity'],
                        'filename': rule_info['filename'],
                    }
                    cve_index[cve_id].append(entry)

        self._cve_index = cve_index

        logger.info(
            f"Snort/ET index built: {rules_with_cve} rules with CVE refs, "
            f"{len(cve_index)} unique CVEs"
        )

        return cve_index

    def get_rules_for_cve(self, cve_id: str) -> List[Dict[str, Any]]:
        """
        Get all IDS rules associated with a CVE.

        Args:
            cve_id: CVE identifier (e.g., 'CVE-2021-44228')

        Returns:
            List of rule info dicts
        """
        if self._cve_index is None:
            self.build_cve_index()
        return self._cve_index.get(cve_id, [])

    def get_indexed_cve_ids(self) -> List[str]:
        """Get list of all CVE IDs with associated rules."""
        if self._cve_index is None:
            self.build_cve_index()
        return list(self._cve_index.keys())

    def get_stats(self) -> Dict[str, int]:
        """Get statistics about the parsed rules."""
        if self._cve_index is None:
            self.build_cve_index()

        total_rules = sum(len(rules) for rules in self._cve_index.values())

        return {
            'unique_cves': len(self._cve_index),
            'total_rule_mappings': total_rules,
        }
