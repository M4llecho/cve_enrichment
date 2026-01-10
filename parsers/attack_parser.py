"""
MITRE ATT&CK JSON Parser - extracts Technique->Tactic mappings.
"""

import json
import logging
from pathlib import Path
from typing import Any, Dict, List, Tuple, Optional

logger = logging.getLogger(__name__)


class ATTACKParser:
    """Parser for MITRE ATT&CK Enterprise JSON data."""

    def __init__(self, json_path: Path):
        self.json_path = json_path
        self._data: Optional[Dict[str, Any]] = None
        self._techniques: Optional[Dict[str, Dict[str, Any]]] = None
        self._tactics: Optional[Dict[str, str]] = None

    def _load(self) -> None:
        """Load and parse the JSON file."""
        if self._data is not None:
            return

        logger.info(f"Loading ATT&CK JSON from {self.json_path}...")
        try:
            with open(self.json_path, "r", encoding="utf-8") as f:
                self._data = json.load(f)
            logger.info("ATT&CK JSON loaded successfully")
        except (json.JSONDecodeError, IOError) as e:
            logger.error(f"Error loading ATT&CK JSON: {e}")
            raise

    def _build_tactic_lookup(self) -> Dict[str, str]:
        """
        Build a lookup table from tactic short name to tactic name.

        Returns: {tactic_short_name: tactic_name}
        """
        if self._tactics is not None:
            return self._tactics

        self._load()

        tactics = {}
        for obj in self._data.get("objects", []):
            if obj.get("type") != "x-mitre-tactic":
                continue

            # Get the short name from x_mitre_shortname
            short_name = obj.get("x_mitre_shortname")
            name = obj.get("name")

            if short_name and name:
                tactics[short_name] = name

        self._tactics = tactics
        logger.debug(f"Built tactic lookup with {len(tactics)} entries")
        return tactics

    def _build_technique_lookup(self) -> Dict[str, Dict[str, Any]]:
        """
        Build a lookup table of techniques.

        Returns: {technique_id: {name, tactics, ...}}
        """
        if self._techniques is not None:
            return self._techniques

        self._load()
        tactic_lookup = self._build_tactic_lookup()

        techniques = {}
        for obj in self._data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue

            # Skip revoked or deprecated techniques
            if obj.get("revoked", False) or obj.get("x_mitre_deprecated", False):
                continue

            # Get technique ID from external references
            technique_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    break

            if not technique_id:
                continue

            name = obj.get("name")

            # Extract tactics from kill_chain_phases
            tactics = []
            for phase in obj.get("kill_chain_phases", []):
                if phase.get("kill_chain_name") == "mitre-attack":
                    phase_name = phase.get("phase_name")
                    if phase_name:
                        tactic_name = tactic_lookup.get(phase_name, phase_name)
                        tactics.append({
                            "id": phase_name,
                            "name": tactic_name,
                        })

            techniques[technique_id] = {
                "id": technique_id,
                "name": name,
                "tactics": tactics,
                "description": obj.get("description", "")[:500],
            }

        self._techniques = techniques
        logger.debug(f"Built technique lookup with {len(techniques)} entries")
        return techniques

    def get_technique_tactic_mappings(self) -> List[Tuple[str, str, str]]:
        """
        Extract Technique to Tactic mappings.

        Returns list of (technique_id, tactic_id, tactic_name) tuples.
        """
        techniques = self._build_technique_lookup()

        mappings = []
        for tech_id, tech_data in techniques.items():
            for tactic in tech_data.get("tactics", []):
                mappings.append((
                    tech_id,
                    tactic["id"],
                    tactic["name"],
                ))

        logger.info(f"Extracted {len(mappings)} Technique->Tactic mappings")
        return mappings

    def get_technique_details(self) -> List[Dict[str, Any]]:
        """
        Get all technique details.

        Returns list of technique dicts.
        """
        techniques = self._build_technique_lookup()
        return list(techniques.values())

    def get_technique_name(self, technique_id: str) -> Optional[str]:
        """Get the name of a technique by ID."""
        techniques = self._build_technique_lookup()
        tech = techniques.get(technique_id)
        return tech["name"] if tech else None

    def get_tactics_for_technique(
        self, technique_id: str
    ) -> List[Tuple[str, str]]:
        """
        Get tactics for a technique.

        Returns list of (tactic_id, tactic_name) tuples.
        """
        techniques = self._build_technique_lookup()
        tech = techniques.get(technique_id)

        if not tech:
            # Try with parent technique (for sub-techniques like T1059.001)
            if "." in technique_id:
                parent_id = technique_id.split(".")[0]
                tech = techniques.get(parent_id)

        if not tech:
            return []

        return [(t["id"], t["name"]) for t in tech.get("tactics", [])]

    def parse_all(self) -> Dict[str, Any]:
        """
        Parse all ATT&CK data.

        Returns dict with 'techniques' and 'mappings' keys.
        """
        return {
            "techniques": self.get_technique_details(),
            "mappings": self.get_technique_tactic_mappings(),
        }
