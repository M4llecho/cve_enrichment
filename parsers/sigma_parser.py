"""
SigmaHQ rules parser - extracts CVE references from Sigma detection rules.
"""

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)

# Pattern to match CVE references in tags
# Matches: cve.2021.44228, attack.cve.2021.44228, cve-2021-44228
CVE_TAG_PATTERN = re.compile(
    r'(?:attack\.)?cve[.\-_](\d{4})[.\-_](\d+)',
    re.IGNORECASE
)

# Pattern to match CVE references in title/description/path
# Matches: CVE-2021-44228, CVE_2021_44228, cve-2021-44228
CVE_TEXT_PATTERN = re.compile(
    r'CVE[.\-_](\d{4})[.\-_](\d+)',
    re.IGNORECASE
)


class SigmaParser:
    """Parser for SigmaHQ detection rules to extract CVE mappings."""

    # Directory in SigmaHQ repo that contains CVE-related rules
    RULES_DIRS = [
        "rules-emerging-threats",
    ]

    def __init__(self, base_dir: Path):
        """
        Initialize the Sigma parser.

        Args:
            base_dir: Path to the extracted Sigma repository base directory
        """
        self.base_dir = base_dir
        self._cve_index: Optional[Dict[str, List[Dict[str, Any]]]] = None

    def _extract_cve_from_tags(self, tags: List[str]) -> List[str]:
        """
        Extract CVE IDs from a list of tags.

        Args:
            tags: List of tag strings from a Sigma rule

        Returns:
            List of CVE IDs in format CVE-YYYY-NNNNN
        """
        cve_ids = []
        for tag in tags:
            match = CVE_TAG_PATTERN.search(tag)
            if match:
                year = match.group(1)
                number = match.group(2)
                cve_id = f"CVE-{year}-{number}"
                cve_ids.append(cve_id)
        return cve_ids

    def _extract_cve_from_text(self, text: str) -> List[str]:
        """
        Extract CVE IDs from text (title, description, path).

        Args:
            text: Text string to search for CVE references

        Returns:
            List of CVE IDs in format CVE-YYYY-NNNNN
        """
        cve_ids = []
        for match in CVE_TEXT_PATTERN.finditer(text):
            year = match.group(1)
            number = match.group(2)
            cve_id = f"CVE-{year}-{number}"
            if cve_id not in cve_ids:
                cve_ids.append(cve_id)
        return cve_ids

    def _parse_rule_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """
        Parse a single Sigma rule file.

        Args:
            file_path: Path to the YAML rule file

        Returns:
            Dict with rule info if it contains CVE references, None otherwise
        """
        # First check if path contains CVE reference (fast check, no file I/O)
        path_str = str(file_path)
        cve_ids = self._extract_cve_from_text(path_str)

        # If no CVE in path, skip this file entirely (don't parse YAML)
        if not cve_ids:
            return None

        # CVE found in path, now parse YAML to get rule details
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                rule = yaml.safe_load(f)

            if not rule or not isinstance(rule, dict):
                return None

            # Get relative path for URL construction
            try:
                rel_path = file_path.relative_to(self.base_dir)
                filename = str(rel_path).replace('\\', '/')
            except ValueError:
                filename = file_path.name

            # Build rule info
            rule_info = {
                'id': rule.get('id', ''),
                'title': rule.get('title', file_path.stem),
                'level': rule.get('level', 'unknown'),
                'filename': filename,
                'cve_ids': cve_ids,
            }

            return rule_info

        except yaml.YAMLError as e:
            logger.debug(f"YAML error parsing {file_path}: {e}")
            return None
        except Exception as e:
            logger.debug(f"Error parsing {file_path}: {e}")
            return None

    def build_cve_index(self, force_rebuild: bool = False) -> Dict[str, List[Dict[str, Any]]]:
        """
        Build an index mapping CVE IDs to their associated Sigma rules.

        Args:
            force_rebuild: Force rebuilding the index even if cached

        Returns:
            Dict mapping CVE-ID to list of rule info dicts
        """
        if self._cve_index is not None and not force_rebuild:
            return self._cve_index

        logger.info("Building Sigma CVE index...")

        cve_index: Dict[str, List[Dict[str, Any]]] = {}
        rule_count = 0
        cve_rule_count = 0

        # Find all YAML files in all rules directories
        if not self.base_dir.exists():
            logger.error(f"Sigma base directory does not exist: {self.base_dir}")
            return {}

        yaml_files = []
        for rules_subdir in self.RULES_DIRS:
            rules_path = self.base_dir / rules_subdir
            if rules_path.exists():
                yaml_files.extend(rules_path.rglob('*.yml'))
                yaml_files.extend(rules_path.rglob('*.yaml'))
                logger.debug(f"Found rules in {rules_subdir}")

        logger.info(f"Found {len(yaml_files)} rule files to parse")

        for file_path in yaml_files:
            rule_count += 1
            rule_info = self._parse_rule_file(file_path)

            if rule_info:
                cve_rule_count += 1
                # Add rule to index for each CVE it references
                for cve_id in rule_info['cve_ids']:
                    if cve_id not in cve_index:
                        cve_index[cve_id] = []

                    # Create rule entry without cve_ids (redundant in index)
                    entry = {
                        'id': rule_info['id'],
                        'title': rule_info['title'],
                        'level': rule_info['level'],
                        'filename': rule_info['filename'],
                    }
                    cve_index[cve_id].append(entry)

        self._cve_index = cve_index

        logger.info(
            f"Sigma index built: {rule_count} rules parsed, "
            f"{cve_rule_count} rules with CVE references, "
            f"{len(cve_index)} unique CVEs"
        )

        return cve_index

    def get_rules_for_cve(self, cve_id: str) -> List[Dict[str, Any]]:
        """
        Get all Sigma rules associated with a CVE.

        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228)

        Returns:
            List of rule info dicts
        """
        if self._cve_index is None:
            self.build_cve_index()

        return self._cve_index.get(cve_id, [])

    def get_indexed_cve_ids(self) -> List[str]:
        """Get list of all CVE IDs that have associated Sigma rules."""
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
