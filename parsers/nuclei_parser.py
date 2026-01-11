"""
Nuclei templates parser - extracts CVE references from ProjectDiscovery templates.
"""

import logging
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

import yaml

logger = logging.getLogger(__name__)

# Pattern to match CVE ID from filename
CVE_FILENAME_PATTERN = re.compile(r'(CVE-\d{4}-\d+)\.ya?ml$', re.IGNORECASE)


class NucleiParser:
    """Parser for Nuclei templates to extract CVE mappings."""

    def __init__(self, base_dir: Path):
        """
        Initialize the Nuclei parser.

        Args:
            base_dir: Path to the extracted Nuclei repository base directory
        """
        self.base_dir = base_dir
        self._cve_index: Optional[Dict[str, List[Dict[str, Any]]]] = None

    def _extract_cve_from_filename(self, filename: str) -> Optional[str]:
        """
        Extract CVE ID from filename.

        Args:
            filename: Filename like CVE-2021-44228.yaml

        Returns:
            CVE ID in format CVE-YYYY-NNNNN or None
        """
        match = CVE_FILENAME_PATTERN.search(filename)
        if match:
            return match.group(1).upper()
        return None

    def _parse_template_file(self, file_path: Path) -> Optional[Dict[str, Any]]:
        """
        Parse a single Nuclei template file.

        Args:
            file_path: Path to the YAML template file

        Returns:
            Dict with template info if it's a CVE template, None otherwise
        """
        # First check if filename contains CVE reference (fast check)
        cve_id = self._extract_cve_from_filename(file_path.name)
        if not cve_id:
            return None

        # CVE found in filename, now parse YAML to get template details
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                template = yaml.safe_load(f)

            if not template or not isinstance(template, dict):
                return None

            # Get relative path for URL construction
            try:
                rel_path = file_path.relative_to(self.base_dir)
                filename = str(rel_path).replace('\\', '/')
            except ValueError:
                filename = file_path.name

            # Extract info section
            info = template.get('info', {})
            if not isinstance(info, dict):
                info = {}

            # Extract metadata section
            metadata = template.get('metadata', {})
            if not isinstance(metadata, dict):
                metadata = {}

            # Build template info
            template_info = {
                'id': template.get('id', cve_id),
                'name': info.get('name', file_path.stem),
                'severity': info.get('severity', 'unknown'),
                'filename': filename,
                'verified': metadata.get('verified', False),
                'vendor': metadata.get('vendor', ''),
                'product': metadata.get('product', ''),
                'cve_id': cve_id,
            }

            return template_info

        except yaml.YAMLError as e:
            logger.debug(f"YAML error parsing {file_path}: {e}")
            return None
        except Exception as e:
            logger.debug(f"Error parsing {file_path}: {e}")
            return None

    def build_cve_index(self, force_rebuild: bool = False) -> Dict[str, List[Dict[str, Any]]]:
        """
        Build an index mapping CVE IDs to their associated Nuclei templates.

        Args:
            force_rebuild: Force rebuilding the index even if cached

        Returns:
            Dict mapping CVE-ID to list of template info dicts
        """
        if self._cve_index is not None and not force_rebuild:
            return self._cve_index

        logger.info("Building Nuclei CVE index...")

        cve_index: Dict[str, List[Dict[str, Any]]] = {}
        template_count = 0
        cve_template_count = 0

        # Find CVE templates in http/cves/
        if not self.base_dir.exists():
            logger.error(f"Nuclei base directory does not exist: {self.base_dir}")
            return {}

        cves_dir = self.base_dir / "http" / "cves"
        if not cves_dir.exists():
            logger.error(f"Nuclei CVE directory does not exist: {cves_dir}")
            return {}

        # Find all YAML files in http/cves/*/
        yaml_files = list(cves_dir.rglob('*.yaml'))
        yaml_files.extend(cves_dir.rglob('*.yml'))

        logger.info(f"Found {len(yaml_files)} template files to parse")

        for file_path in yaml_files:
            template_count += 1
            template_info = self._parse_template_file(file_path)

            if template_info:
                cve_template_count += 1
                cve_id = template_info['cve_id']

                if cve_id not in cve_index:
                    cve_index[cve_id] = []

                # Create entry without cve_id (redundant in index)
                entry = {
                    'id': template_info['id'],
                    'name': template_info['name'],
                    'severity': template_info['severity'],
                    'filename': template_info['filename'],
                    'verified': template_info['verified'],
                    'vendor': template_info['vendor'],
                    'product': template_info['product'],
                }
                cve_index[cve_id].append(entry)

        self._cve_index = cve_index

        logger.info(
            f"Nuclei index built: {template_count} templates parsed, "
            f"{cve_template_count} CVE templates found, "
            f"{len(cve_index)} unique CVEs"
        )

        return cve_index

    def get_templates_for_cve(self, cve_id: str) -> List[Dict[str, Any]]:
        """
        Get all Nuclei templates associated with a CVE.

        Args:
            cve_id: CVE identifier (e.g., CVE-2021-44228)

        Returns:
            List of template info dicts
        """
        if self._cve_index is None:
            self.build_cve_index()

        return self._cve_index.get(cve_id, [])

    def get_indexed_cve_ids(self) -> List[str]:
        """Get list of all CVE IDs that have associated Nuclei templates."""
        if self._cve_index is None:
            self.build_cve_index()

        return list(self._cve_index.keys())

    def get_stats(self) -> Dict[str, int]:
        """Get statistics about the parsed templates."""
        if self._cve_index is None:
            self.build_cve_index()

        total_templates = sum(len(templates) for templates in self._cve_index.values())
        verified_count = sum(
            1 for templates in self._cve_index.values()
            for t in templates if t.get('verified', False)
        )

        return {
            'unique_cves': len(self._cve_index),
            'total_template_mappings': total_templates,
            'verified_templates': verified_count,
        }
