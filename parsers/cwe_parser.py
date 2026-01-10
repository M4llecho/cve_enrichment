"""
CWE XML Parser - extracts CWE details and CWE->CAPEC mappings.
"""

import logging
from pathlib import Path
from typing import Dict, List, Tuple, Any
from lxml import etree

logger = logging.getLogger(__name__)

# CWE XML namespace
CWE_NS = {"cwe": "http://cwe.mitre.org/cwe-7"}


class CWEParser:
    """Parser for CWE XML data."""

    def __init__(self, xml_path: Path):
        self.xml_path = xml_path
        self._tree = None
        self._root = None

    def _load(self) -> None:
        """Load and parse the XML file."""
        if self._root is not None:
            return

        logger.info(f"Loading CWE XML from {self.xml_path}...")
        try:
            self._tree = etree.parse(str(self.xml_path))
            self._root = self._tree.getroot()
            logger.info("CWE XML loaded successfully")
        except etree.XMLSyntaxError as e:
            logger.error(f"Error parsing CWE XML: {e}")
            raise

    def get_cwe_details(self) -> List[Dict[str, str]]:
        """
        Extract CWE details (ID, name, description).

        Returns list of dicts with cwe_id, cwe_name, description.
        """
        self._load()

        weaknesses = []

        # Find all Weakness elements
        for weakness in self._root.findall(".//cwe:Weakness", CWE_NS):
            cwe_id = weakness.get("ID")
            cwe_name = weakness.get("Name")

            if not cwe_id:
                continue

            # Get description
            description = None
            desc_elem = weakness.find("cwe:Description", CWE_NS)
            if desc_elem is not None and desc_elem.text:
                description = desc_elem.text.strip()

            # Extended description if main is empty
            if not description:
                ext_desc = weakness.find("cwe:Extended_Description", CWE_NS)
                if ext_desc is not None:
                    # Get all text content
                    description = "".join(ext_desc.itertext()).strip()

            weaknesses.append({
                "cwe_id": f"CWE-{cwe_id}",
                "cwe_name": cwe_name,
                "description": description[:2000] if description else None,
            })

        logger.info(f"Extracted {len(weaknesses)} CWE details")
        return weaknesses

    def get_cwe_capec_mappings(self) -> List[Tuple[str, str]]:
        """
        Extract CWE to CAPEC mappings.

        Returns list of (cwe_id, capec_id) tuples.
        """
        self._load()

        mappings = []

        # Find all Weakness elements
        for weakness in self._root.findall(".//cwe:Weakness", CWE_NS):
            cwe_id = weakness.get("ID")
            if not cwe_id:
                continue

            cwe_id = f"CWE-{cwe_id}"

            # Look for Related Attack Patterns
            related_patterns = weakness.find("cwe:Related_Attack_Patterns", CWE_NS)
            if related_patterns is None:
                continue

            for pattern in related_patterns.findall("cwe:Related_Attack_Pattern", CWE_NS):
                capec_id = pattern.get("CAPEC_ID")
                if capec_id:
                    mappings.append((cwe_id, f"CAPEC-{capec_id}"))

        logger.info(f"Extracted {len(mappings)} CWE->CAPEC mappings")
        return mappings

    def parse_all(self) -> Dict[str, Any]:
        """
        Parse all CWE data.

        Returns dict with 'details' and 'mappings' keys.
        """
        return {
            "details": self.get_cwe_details(),
            "mappings": self.get_cwe_capec_mappings(),
        }
