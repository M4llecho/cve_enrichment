"""
CAPEC XML Parser - extracts CAPEC->ATT&CK Technique mappings.
"""

import logging
import re
from pathlib import Path
from typing import Dict, List, Tuple, Any
from lxml import etree

logger = logging.getLogger(__name__)

# CAPEC XML namespace
CAPEC_NS = {"capec": "http://capec.mitre.org/capec-3"}


class CAPECParser:
    """Parser for CAPEC XML data."""

    def __init__(self, xml_path: Path):
        self.xml_path = xml_path
        self._tree = None
        self._root = None

    def _load(self) -> None:
        """Load and parse the XML file."""
        if self._root is not None:
            return

        logger.info(f"Loading CAPEC XML from {self.xml_path}...")
        try:
            self._tree = etree.parse(str(self.xml_path))
            self._root = self._tree.getroot()
            logger.info("CAPEC XML loaded successfully")
        except etree.XMLSyntaxError as e:
            logger.error(f"Error parsing CAPEC XML: {e}")
            raise

    def get_capec_technique_mappings(self) -> List[Tuple[str, str, str]]:
        """
        Extract CAPEC to ATT&CK Technique mappings.

        Returns list of (capec_id, technique_id, technique_name) tuples.
        The technique_name is extracted from the Taxonomy_Mapping if available.
        """
        self._load()

        mappings = []

        # Find all Attack_Pattern elements
        for pattern in self._root.findall(".//capec:Attack_Pattern", CAPEC_NS):
            capec_id = pattern.get("ID")
            if not capec_id:
                continue

            capec_id = f"CAPEC-{capec_id}"

            # Look for Taxonomy Mappings
            tax_mappings = pattern.find("capec:Taxonomy_Mappings", CAPEC_NS)
            if tax_mappings is None:
                continue

            for tax_mapping in tax_mappings.findall("capec:Taxonomy_Mapping", CAPEC_NS):
                taxonomy_name = tax_mapping.get("Taxonomy_Name", "")

                # Check if it's ATT&CK (XML uses "ATTACK" without &)
                if "ATTACK" not in taxonomy_name.upper():
                    continue

                # Get Entry ID (technique ID)
                entry_id_elem = tax_mapping.find("capec:Entry_ID", CAPEC_NS)
                if entry_id_elem is None or not entry_id_elem.text:
                    continue

                technique_id = entry_id_elem.text.strip()

                # Normalize technique ID format
                if not technique_id.startswith("T"):
                    technique_id = f"T{technique_id}"

                # Get Entry Name (technique name)
                entry_name_elem = tax_mapping.find("capec:Entry_Name", CAPEC_NS)
                technique_name = None
                if entry_name_elem is not None and entry_name_elem.text:
                    technique_name = entry_name_elem.text.strip()

                mappings.append((capec_id, technique_id, technique_name))

        # Deduplicate while preserving order
        seen = set()
        unique_mappings = []
        for mapping in mappings:
            key = (mapping[0], mapping[1])
            if key not in seen:
                seen.add(key)
                unique_mappings.append(mapping)

        logger.info(f"Extracted {len(unique_mappings)} CAPEC->Technique mappings")
        return unique_mappings

    def get_capec_details(self) -> List[Dict[str, Any]]:
        """
        Extract CAPEC details (ID, name, description).

        Returns list of dicts with capec_id, name, description.
        """
        self._load()

        patterns = []

        for pattern in self._root.findall(".//capec:Attack_Pattern", CAPEC_NS):
            capec_id = pattern.get("ID")
            name = pattern.get("Name")

            if not capec_id:
                continue

            # Get description
            description = None
            desc_elem = pattern.find("capec:Description", CAPEC_NS)
            if desc_elem is not None:
                description = "".join(desc_elem.itertext()).strip()

            patterns.append({
                "capec_id": f"CAPEC-{capec_id}",
                "name": name,
                "description": description[:2000] if description else None,
            })

        logger.info(f"Extracted {len(patterns)} CAPEC details")
        return patterns

    def parse_all(self) -> Dict[str, Any]:
        """
        Parse all CAPEC data.

        Returns dict with 'details' and 'mappings' keys.
        """
        return {
            "details": self.get_capec_details(),
            "mappings": self.get_capec_technique_mappings(),
        }
