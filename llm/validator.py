"""
Tag Coherence Validator for CVE tagging.

This module validates and corrects logical inconsistencies in LLM-generated tags.
It ensures that kill_chain_phases, prerequisites, and capabilities are coherent
with each other and with CVSS vector data.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)


class TagCoherenceValidator:
    """
    Validates and corrects tag coherence based on logical rules.

    Rules implemented:
    - R1: privilege_escalation + requires_privilege is inconsistent
    - R2: initial_access + requires_local is a conflict (initial access is typically remote)
    - R3: grants_admin_access implies grants_user_access (don't duplicate)
    - R4: grants_code_execution without kill_chain_phase -> add execution
    - R5: credential_access without grants_credential_access -> add capability
    - R6: persistence without grants_persistence -> add capability
    - R7: CVSS AV:N but missing requires_network -> add prerequisite
    - R8: CVSS PR:N but has requires_privilege -> remove erroneous prerequisite
    """

    def __init__(self):
        self.corrections_log: List[str] = []

    def validate_and_correct(
        self,
        tags: Dict[str, List[str]],
        cvss_vector: Optional[str] = None
    ) -> Dict[str, List[str]]:
        """
        Validate tags and apply corrections for coherence.

        Args:
            tags: Dictionary with kill_chain_phases, prerequisites, capabilities
            cvss_vector: Optional CVSS vector string for additional validation

        Returns:
            Corrected tags dictionary
        """
        self.corrections_log = []

        # Make mutable copies
        phases = list(tags.get("kill_chain_phases", []))
        prereqs = list(tags.get("prerequisites", []))
        caps = list(tags.get("capabilities", []))

        # Parse CVSS if provided
        cvss_data = self._parse_cvss(cvss_vector) if cvss_vector else {}

        # Apply rules
        phases, prereqs, caps = self._apply_r1_privilege_escalation(phases, prereqs, caps)
        phases, prereqs, caps = self._apply_r2_initial_access_local(phases, prereqs, caps)
        phases, prereqs, caps = self._apply_r3_admin_implies_user(phases, prereqs, caps)
        phases, prereqs, caps = self._apply_r4_code_execution_phase(phases, prereqs, caps)
        phases, prereqs, caps = self._apply_r5_credential_access(phases, prereqs, caps)
        phases, prereqs, caps = self._apply_r6_persistence(phases, prereqs, caps)

        # CVSS-based rules
        if cvss_data:
            phases, prereqs, caps = self._apply_r7_cvss_network(phases, prereqs, caps, cvss_data)
            phases, prereqs, caps = self._apply_r8_cvss_privilege(phases, prereqs, caps, cvss_data)

        # Log corrections if any
        if self.corrections_log:
            logger.debug(f"Tag corrections applied: {self.corrections_log}")

        return {
            "kill_chain_phases": phases,
            "prerequisites": prereqs,
            "capabilities": caps
        }

    def _parse_cvss(self, cvss_vector: str) -> Dict[str, str]:
        """Parse CVSS vector into components."""
        if not cvss_vector or cvss_vector == "N/A":
            return {}

        result = {}
        # Handle both CVSS 3.x and 2.0 formats
        # CVSS 3.x: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        # CVSS 2.0: AV:N/AC:L/Au:N/C:P/I:P/A:P

        parts = cvss_vector.split("/")
        for part in parts:
            if ":" in part:
                key, value = part.split(":", 1)
                result[key.upper()] = value.upper()

        return result

    def _apply_r1_privilege_escalation(
        self,
        phases: List[str],
        prereqs: List[str],
        caps: List[str]
    ) -> Tuple[List[str], List[str], List[str]]:
        """
        R1: privilege_escalation + requires_privilege is inconsistent.
        If exploiting for privilege escalation, you shouldn't already have privileges.
        """
        if "privilege_escalation" in phases and "requires_privilege" in prereqs:
            prereqs.remove("requires_privilege")
            self.corrections_log.append("R1: Removed requires_privilege (inconsistent with privilege_escalation)")

        return phases, prereqs, caps

    def _apply_r2_initial_access_local(
        self,
        phases: List[str],
        prereqs: List[str],
        caps: List[str]
    ) -> Tuple[List[str], List[str], List[str]]:
        """
        R2: initial_access + requires_local is typically a conflict.
        Initial access is usually remote. Log warning but don't auto-correct
        as there are edge cases (USB attacks, etc).
        """
        if "initial_access" in phases and "requires_local" in prereqs:
            # Don't remove, but log warning - could be legitimate (USB attack, etc)
            logger.debug("R2: initial_access with requires_local - unusual but may be valid (physical/USB attack)")

        return phases, prereqs, caps

    def _apply_r3_admin_implies_user(
        self,
        phases: List[str],
        prereqs: List[str],
        caps: List[str]
    ) -> Tuple[List[str], List[str], List[str]]:
        """
        R3: grants_admin_access implies grants_user_access.
        Don't add both - admin is superset of user.
        """
        if "grants_admin_access" in caps and "grants_user_access" in caps:
            caps.remove("grants_user_access")
            self.corrections_log.append("R3: Removed grants_user_access (implied by grants_admin_access)")

        return phases, prereqs, caps

    def _apply_r4_code_execution_phase(
        self,
        phases: List[str],
        prereqs: List[str],
        caps: List[str]
    ) -> Tuple[List[str], List[str], List[str]]:
        """
        R4: grants_code_execution without kill_chain_phase should add execution.
        """
        if "grants_code_execution" in caps and not phases:
            phases.append("execution")
            self.corrections_log.append("R4: Added execution phase (has grants_code_execution)")

        return phases, prereqs, caps

    def _apply_r5_credential_access(
        self,
        phases: List[str],
        prereqs: List[str],
        caps: List[str]
    ) -> Tuple[List[str], List[str], List[str]]:
        """
        R5: credential_access phase should have grants_credential_access capability.
        """
        if "credential_access" in phases and "grants_credential_access" not in caps:
            caps.append("grants_credential_access")
            self.corrections_log.append("R5: Added grants_credential_access (credential_access phase)")

        return phases, prereqs, caps

    def _apply_r6_persistence(
        self,
        phases: List[str],
        prereqs: List[str],
        caps: List[str]
    ) -> Tuple[List[str], List[str], List[str]]:
        """
        R6: persistence phase should have grants_persistence capability.
        """
        if "persistence" in phases and "grants_persistence" not in caps:
            caps.append("grants_persistence")
            self.corrections_log.append("R6: Added grants_persistence (persistence phase)")

        return phases, prereqs, caps

    def _apply_r7_cvss_network(
        self,
        phases: List[str],
        prereqs: List[str],
        caps: List[str],
        cvss_data: Dict[str, str]
    ) -> Tuple[List[str], List[str], List[str]]:
        """
        R7: CVSS AV:N but missing requires_network -> add prerequisite.
        """
        av = cvss_data.get("AV", "")
        if av == "N" and "requires_network" not in prereqs:
            prereqs.append("requires_network")
            self.corrections_log.append("R7: Added requires_network (CVSS AV:N)")

        return phases, prereqs, caps

    def _apply_r8_cvss_privilege(
        self,
        phases: List[str],
        prereqs: List[str],
        caps: List[str],
        cvss_data: Dict[str, str]
    ) -> Tuple[List[str], List[str], List[str]]:
        """
        R8: CVSS PR:N (or Au:N for v2) but has requires_privilege -> remove erroneous prerequisite.
        """
        # CVSS 3.x uses PR (Privileges Required)
        pr = cvss_data.get("PR", "")
        # CVSS 2.0 uses Au (Authentication)
        au = cvss_data.get("AU", "")

        if (pr == "N" or au == "N") and "requires_privilege" in prereqs:
            prereqs.remove("requires_privilege")
            self.corrections_log.append("R8: Removed requires_privilege (CVSS PR:N or Au:N)")

        return phases, prereqs, caps

    def get_corrections_log(self) -> List[str]:
        """Return list of corrections applied in last validation."""
        return self.corrections_log.copy()


# Default validator instance
DEFAULT_VALIDATOR = TagCoherenceValidator()


def validate_tag_coherence(
    tags: Dict[str, List[str]],
    cvss_vector: Optional[str] = None
) -> Dict[str, List[str]]:
    """
    Convenience function to validate and correct tag coherence.

    Args:
        tags: Dictionary with kill_chain_phases, prerequisites, capabilities
        cvss_vector: Optional CVSS vector string

    Returns:
        Corrected tags dictionary
    """
    return DEFAULT_VALIDATOR.validate_and_correct(tags, cvss_vector)
