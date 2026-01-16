"""
Prompt templates for CVE tagging.

Optimized for:
1. Minimal context - only essential fields for kill chain tagging
2. Clear JSON output instructions
3. Compatibility with reasoning models (DeepSeek-R1)
"""

from typing import Any, Dict

from .taxonomy import KILL_CHAIN_PHASES, PREREQUISITES, CAPABILITIES


SYSTEM_PROMPT = """You are a cybersecurity expert. Analyze CVE data and output JSON tags.

OUTPUT FORMAT - Respond with ONLY this JSON structure, nothing else:
{"kill_chain_phases":[],"prerequisites":[],"capabilities":[]}

RULES:
1. Output ONLY valid JSON - no explanations, no markdown
2. Use ONLY tags from the provided lists
3. Arrays can have multiple tags or be empty"""


def build_cve_analysis_prompt(cve_data: Dict[str, Any]) -> str:
    """
    Build minimal prompt with essential fields and strict mapping logic.
    Includes CPE data to help determine kill chain context.
    """
    cve_id = cve_data.get("cve_id", "Unknown")
    description = cve_data.get("description", "")[:500]
    cvss_vector = cve_data.get("cvss_vector", "N/A")
    cwe_ids = cve_data.get("cwe_ids", []) or []

    # CPE data for context
    vendors = cve_data.get("affected_vendors", []) or []
    products = cve_data.get("affected_products", []) or []
    products_detail = cve_data.get("affected_products_detail", []) or []

    # Determine software types from CPE parts
    parts = set()
    for detail in products_detail:
        if isinstance(detail, dict) and detail.get("part"):
            parts.add(detail["part"])
    part_types = []
    if "a" in parts: part_types.append("application")
    if "o" in parts: part_types.append("OS")
    if "h" in parts: part_types.append("hardware")

    # Exploitation indicators
    flags = []
    if cve_data.get("in_kev"): flags.append("KEV")
    if cve_data.get("kev_ransomware_use"): flags.append("RANSOMWARE")
    if cve_data.get("has_exploit"): flags.append("EXPLOIT_PUBLIC")
    flags_str = ", ".join(flags) if flags else "None"

    # Build CPE context line
    cpe_context = ""
    if vendors or products:
        vendors_str = ", ".join(vendors[:3]) if vendors else "N/A"
        products_str = ", ".join(products[:3]) if products else "N/A"
        type_str = "/".join(part_types) if part_types else "N/A"
        cpe_context = f"\nVendors: {vendors_str}\nProducts: {products_str}\nType: {type_str}"

    # Prompt strutturato per modelli Reasoning
    prompt = f"""### CVE DATA
ID: {cve_id}
Description: {description}
CVSS: {cvss_vector}
CWE: {", ".join(cwe_ids[:3]) if cwe_ids else "N/A"}{cpe_context}
Flags: {flags_str}

### TAGS LIST
kill_chain_phases: {", ".join(KILL_CHAIN_PHASES.tags.keys())}
prerequisites: {", ".join(PREREQUISITES.tags.keys())}
capabilities: {", ".join(CAPABILITIES.tags.keys())}

### MAPPING RULES (STRICT):
1. PREREQUISITES from CVSS:
   - AV:N -> requires_network
   - AV:L -> requires_local
   - AV:P -> requires_physical
   - PR:L or PR:H -> requires_privilege (NOT if PR:N)
   - UI:R -> requires_user_interaction

2. CAPABILITIES from CVSS:
   - C:H + I:H -> grants_admin_access
   - C:H or C:L -> grants_data_access
   - A:H only -> grants_dos

3. COHERENCE (CRITICAL):
   - privilege_escalation means user GAINS privileges, so requires_privilege=NO
   - initial_access is typically remote (requires_network), rarely requires_local
   - credential_access phase should have grants_credential_access capability

4. CONTEXT from Type:
   - OS vulnerabilities: often privilege_escalation, persistence
   - Web/application: often initial_access, execution
   - Network devices: lateral_movement, command_and_control

Analyze and output JSON:"""

    return prompt

def _format_tag_options_compact() -> str:
    """Format tag options in compact format for prompt."""
    lines = []
    lines.append("kill_chain_phases: " + ", ".join(KILL_CHAIN_PHASES.tags.keys()))
    lines.append("prerequisites: " + ", ".join(PREREQUISITES.tags.keys()))
    lines.append("capabilities: " + ", ".join(CAPABILITIES.tags.keys()))
    return "\n".join(lines)
