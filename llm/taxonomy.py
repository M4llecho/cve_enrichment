"""
CVE Tag Taxonomy definitions for kill chain reconstruction.

This module defines all valid tags organized by category:
- Kill Chain Phases: where in the attack chain this CVE fits
- Prerequisites: what's needed to exploit this CVE (input for chaining)
- Capabilities: what you gain from exploiting this CVE (output for chaining)

Chaining logic: CVE-A -> CVE-B if capabilities(A) satisfies prerequisites(B)
"""

from dataclasses import dataclass
from typing import Dict, List, Set

# Version of the taxonomy (for tracking changes)
TAXONOMY_VERSION = "1.0.0"


@dataclass
class TagCategory:
    """Definition of a tag category."""
    name: str
    description: str
    tags: Dict[str, str]  # tag_id -> description

    def validate_tags(self, tags: List[str]) -> List[str]:
        """Return only valid tags from input list."""
        return [t for t in tags if t in self.tags]

    def get_tag_ids(self) -> List[str]:
        """Return list of all tag IDs in this category."""
        return list(self.tags.keys())


# =============================================================================
# KILL CHAIN PHASES (12 tags)
# Where this CVE fits in the attack chain (based on MITRE ATT&CK)
# =============================================================================

KILL_CHAIN_PHASES = TagCategory(
    name="kill_chain_phases",
    description="Where in the attack chain this CVE can be used",
    tags={
        "initial_access": "First entry point into the target system",
        "execution": "Running malicious code on target",
        "persistence": "Maintaining access across restarts",
        "privilege_escalation": "Gaining higher privileges",
        "defense_evasion": "Avoiding security controls and detection",
        "credential_access": "Stealing credentials or secrets",
        "discovery": "Learning about the target environment",
        "lateral_movement": "Moving to other systems in the network",
        "collection": "Gathering target data",
        "exfiltration": "Extracting data from target",
        "command_and_control": "Communicating with C2 infrastructure",
        "impact": "Final damage (ransomware, destruction, disruption)",
    }
)


# =============================================================================
# PREREQUISITES (7 tags)
# What's needed to exploit this CVE - INPUT for chaining
# =============================================================================

PREREQUISITES = TagCategory(
    name="prerequisites",
    description="What's required to exploit this CVE (input for chaining)",
    tags={
        "requires_network": "Network access to the target is required",
        "requires_local": "Local access (shell, session) is required",
        "requires_auth": "Valid authentication/credentials required",
        "requires_user_interaction": "User must perform an action (click, open file)",
        "requires_privilege": "Already elevated privileges required",
        "requires_physical": "Physical access to the device required",
        "requires_outbound_connectivity": "Target must initiate connections to attacker (LDAP, reverse shell, HTTP callback)",
    }
)


# =============================================================================
# CAPABILITIES (8 tags)
# What you gain from exploiting this CVE - OUTPUT for chaining
# =============================================================================

CAPABILITIES = TagCategory(
    name="capabilities",
    description="What's gained from exploiting this CVE (output for chaining)",
    tags={
        "grants_code_execution": "Arbitrary code execution capability",
        "grants_admin_access": "Administrative/root/SYSTEM privileges",
        "grants_user_access": "Regular user-level access",
        "grants_credential_access": "Ability to steal/read credentials",
        "grants_network_pivot": "Access to other network systems",
        "grants_persistence": "Ability to install backdoor/maintain access",
        "grants_data_access": "Access to read/modify sensitive data",
        "grants_dos": "Ability to cause denial of service",
    }
)


# =============================================================================
# ALL CATEGORIES
# =============================================================================

ALL_CATEGORIES = [
    KILL_CHAIN_PHASES,
    PREREQUISITES,
    CAPABILITIES,
]

CATEGORY_MAP = {cat.name: cat for cat in ALL_CATEGORIES}


def get_all_valid_tags() -> Set[str]:
    """Get set of all valid tag IDs across all categories."""
    all_tags = set()
    for category in ALL_CATEGORIES:
        all_tags.update(category.tags.keys())
    return all_tags


def validate_tags_by_category(tags_dict: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """
    Validate tags and return only valid ones per category.

    Args:
        tags_dict: Dict with category names as keys and tag lists as values

    Returns:
        Dict with same structure but only valid tags
    """
    validated = {}

    for cat_name, tags in tags_dict.items():
        if cat_name in CATEGORY_MAP:
            validated[cat_name] = CATEGORY_MAP[cat_name].validate_tags(tags)
        else:
            validated[cat_name] = []

    return validated


def get_category_tags_description() -> str:
    """
    Get formatted description of all categories and their tags.
    Useful for prompt generation.
    """
    lines = []
    for category in ALL_CATEGORIES:
        lines.append(f"\n{category.name.upper().replace('_', ' ')}:")
        for tag_id, description in category.tags.items():
            lines.append(f"  - {tag_id}: {description}")
    return "\n".join(lines)
