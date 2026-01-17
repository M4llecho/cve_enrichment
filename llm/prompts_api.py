"""
Prompt templates optimized for cloud API LLMs.

These prompts leverage the superior reasoning capabilities of cloud models
to produce more accurate and contextually-aware CVE tagging.

Key differences from Ollama prompts:
1. Semantic reasoning over mechanical CVSS mapping
2. Explicit anti-patterns to avoid common mistakes
3. Contextual analysis considering attack scenarios
4. Clear distinction between theoretical max impact vs typical exploitation
"""

from typing import Any, Dict

from .taxonomy import KILL_CHAIN_PHASES, PREREQUISITES, CAPABILITIES


API_SYSTEM_PROMPT = """You are an expert security analyst specializing in CVE analysis and MITRE ATT&CK framework mapping. Your task is to analyze vulnerabilities and assign accurate, contextually-aware tags.

CRITICAL REASONING PRINCIPLES:

1. CVSS IS THEORETICAL MAXIMUM, NOT TYPICAL OUTCOME
   - CVSS scores represent worst-case scenarios under ideal conditions
   - C:H/I:H does NOT automatically mean grants_admin_access
   - Actual privileges gained depend on the execution context (service user, container, sandbox)

2. PREREQUISITES MUST REFLECT REAL EXPLOITATION REQUIREMENTS
   - Go beyond network/local - what specific conditions enable exploitation?
   - Consider: Does the application need to process attacker-controlled input?
   - Authentication requirements: Is it truly "no auth" or does it need a valid session?

3. CAPABILITIES REFLECT WHAT YOU ACTUALLY GAIN
   - Code execution as www-data != admin access
   - Remote code execution in a container != host compromise
   - Information disclosure != credential access (unless credentials are exposed)

4. KILL CHAIN PHASES REFLECT ATTACK STAGE
   - initial_access: First foothold, typically exploited remotely without prior access
   - privilege_escalation: Attacker already has LOW privileges, gains HIGHER ones
   - execution: Ability to run arbitrary code (often combined with initial_access)

OUTPUT FORMAT:
Respond with ONLY a valid JSON object, no explanations or markdown:
{"kill_chain_phases":[],"prerequisites":[],"capabilities":[],"confidence":0.0}

CONFIDENCE SCORE (0.0 to 1.0):
- 0.9-1.0: Clear-cut case, description explicitly states the attack vector and impact
- 0.7-0.8: High confidence, can infer from description and CWE type
- 0.5-0.6: Moderate confidence, some ambiguity in description or multiple interpretations
- 0.3-0.4: Low confidence, vague description, guessing based on CWE/product type
- 0.0-0.2: Very uncertain, insufficient information to tag accurately

---

FEW-SHOT EXAMPLES:

EXAMPLE 1 - JNDI Injection (Log4Shell pattern):
Description: "Apache Log4j2 <=2.14.1 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled."
CVSS: AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H (10.0)
CWE: CWE-502 (Deserialization), CWE-400 (Resource Exhaustion), CWE-20 (Input Validation)
Analysis reasoning:
- Kill chain: initial_access (remote, no prior access), execution (runs arbitrary code)
- Prerequisites: requires_network (AV:N), requires_outbound_connectivity (CRITICAL: server must call back to attacker LDAP/RMI server to fetch malicious class)
- Capabilities: grants_code_execution (arbitrary code), grants_user_access (runs as the Java process user - typically tomcat/app user, NOT root)
- Note: NOT grants_admin_access because Java web apps rarely run as root
Output: {"kill_chain_phases":["initial_access","execution"],"prerequisites":["requires_network","requires_outbound_connectivity"],"capabilities":["grants_code_execution","grants_user_access"],"confidence":0.95}

EXAMPLE 2 - SQL Injection:
Description: "SQL injection vulnerability in the search function of ProductCatalog v3.2 allows remote attackers to execute arbitrary SQL commands via the 'query' parameter."
CVSS: AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N (9.1)
CWE: CWE-89 (SQL Injection)
Analysis reasoning:
- Kill chain: initial_access (remote entry point), collection (can extract data)
- Prerequisites: requires_network (AV:N)
- Capabilities: grants_data_access (read/modify database), NOT grants_code_execution (standard SQLi doesn't give shell unless xp_cmdshell or similar)
- Note: Even with C:H/I:H, this is DATA access not CODE execution
Output: {"kill_chain_phases":["initial_access","collection"],"prerequisites":["requires_network"],"capabilities":["grants_data_access"],"confidence":0.9}

EXAMPLE 3 - Local Privilege Escalation:
Description: "A vulnerability in the SUID binary /usr/bin/pkexec in Polkit allows local users to gain root privileges by exploiting a memory corruption bug when processing command-line arguments."
CVSS: AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H (7.8)
CWE: CWE-787 (Out-of-bounds Write)
Analysis reasoning:
- Kill chain: privilege_escalation (requires existing local access, gains higher privs)
- Prerequisites: requires_local (AV:L), requires_privilege (PR:L - needs unprivileged local account)
- Capabilities: grants_code_execution (memory corruption to code exec), grants_admin_access (SUID root binary = actual root)
- Note: This IS grants_admin_access because pkexec is SUID root
Output: {"kill_chain_phases":["privilege_escalation"],"prerequisites":["requires_local","requires_privilege"],"capabilities":["grants_code_execution","grants_admin_access"],"confidence":0.95}

EXAMPLE 4 - Denial of Service:
Description: "The HTTP/2 implementation in nginx before 1.19.7 allows remote attackers to cause a denial of service (CPU consumption) via a crafted HEADERS frame with excessive CONTINUATION frames."
CVSS: AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H (7.5)
CWE: CWE-400 (Resource Exhaustion)
Analysis reasoning:
- Kill chain: impact (direct availability impact, no lateral movement)
- Prerequisites: requires_network (AV:N)
- Capabilities: grants_dos (A:H with C:N/I:N = pure DoS)
- Note: No data access, no code execution - only availability impact
Output: {"kill_chain_phases":["impact"],"prerequisites":["requires_network"],"capabilities":["grants_dos"],"confidence":0.9}

---

Now analyze the CVE provided and respond with ONLY the JSON output."""


def build_api_analysis_prompt(cve_data: Dict[str, Any]) -> str:
    """
    Build detailed prompt for API-based LLM analysis.

    This prompt provides rich context and explicit guidance to leverage
    the superior reasoning capabilities of cloud models.
    """
    cve_id = cve_data.get("cve_id", "Unknown")
    description = cve_data.get("description", "")
    cvss_vector = cve_data.get("cvss_vector", "N/A")
    cvss_score = cve_data.get("cvss_score", "N/A")
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
    if "o" in parts: part_types.append("operating_system")
    if "h" in parts: part_types.append("hardware/firmware")

    # Exploitation indicators
    exploitation_context = []
    if cve_data.get("in_kev"):
        exploitation_context.append("CISA KEV (actively exploited in the wild)")
    if cve_data.get("kev_ransomware_use"):
        exploitation_context.append("Known ransomware use")
    if cve_data.get("has_exploit"):
        exploitation_context.append("Public exploit available")
    if cve_data.get("has_nuclei_template"):
        exploitation_context.append("Nuclei template available")
    if cve_data.get("has_snort_rule"):
        exploitation_context.append("Snort detection rule exists")

    # Build the detailed prompt
    prompt = f"""### CVE ANALYSIS REQUEST

**CVE ID:** {cve_id}

**Description:**
{description}

**Technical Details:**
- CVSS Vector: {cvss_vector}
- CVSS Score: {cvss_score}
- CWE IDs: {", ".join(cwe_ids) if cwe_ids else "Not specified"}
- Affected Vendors: {", ".join(vendors[:5]) if vendors else "Not specified"}
- Affected Products: {", ".join(products[:5]) if products else "Not specified"}
- Software Type: {", ".join(part_types) if part_types else "Not specified"}
- Exploitation Status: {"; ".join(exploitation_context) if exploitation_context else "No known active exploitation"}

---

### AVAILABLE TAGS

**KILL CHAIN PHASES** (select 1-3 most relevant):
{_format_tags_with_descriptions(KILL_CHAIN_PHASES.tags)}

**PREREQUISITES** (what's REQUIRED to exploit - be specific):
{_format_tags_with_descriptions(PREREQUISITES.tags)}

**CAPABILITIES** (what attacker ACTUALLY GAINS - not theoretical maximum):
{_format_tags_with_descriptions(CAPABILITIES.tags)}

---

### ANALYSIS GUIDELINES

**For PREREQUISITES, consider:**
- requires_network: Can be exploited over network (AV:N)
- requires_local: Requires local shell/session access (AV:L)
- requires_auth: Needs valid credentials or authenticated session (different from requires_privilege)
- requires_privilege: Needs ELEVATED privileges (admin/root) to exploit
- requires_user_interaction: User must click link, open file, or trigger action (UI:R)
- requires_physical: Physical device access needed (AV:P)
- requires_outbound_connectivity: TARGET must initiate outbound connections to attacker infrastructure
  (JNDI/LDAP lookups like Log4Shell, reverse shells, SSRF with callback, HTTP beacons).
  If egress filtering blocks outbound connections, exploit fails or is limited.

**For CAPABILITIES, apply these rules:**
- grants_code_execution: Attacker can run arbitrary code
- grants_admin_access: ONLY if exploit gives root/SYSTEM/admin - NOT just because CVSS C:H/I:H
- grants_user_access: Gives unprivileged shell/session (typical for RCE in web apps)
- grants_credential_access: Specifically leaks credentials, tokens, keys
- grants_data_access: Can read/modify data (C:H or I:H without code exec)
- grants_dos: Primary impact is availability (A:H without significant C/I)

**COMMON MISTAKES TO AVOID:**

1. grants_admin_access overuse:
   - RCE in a web application typically gives www-data/tomcat privileges, NOT admin
   - Only use grants_admin_access if the vulnerable process runs as root/SYSTEM
   - Container/sandbox escapes might grant admin inside container but not on host

2. prerequisites underspecification:
   - Web vulnerabilities often need the app to process attacker input (forms, headers, etc.)
   - JNDI injection (like Log4Shell) requires the app to log/process attacker-controlled strings
   - SQL injection requires user input to reach SQL queries

3. Confusing initial_access with privilege_escalation:
   - initial_access: No prior access needed, this IS the entry point
   - privilege_escalation: Already have low-privilege access, gain higher privileges

4. Missing requires_outbound_connectivity:
   - Log4Shell, Spring4Shell, and similar JNDI attacks REQUIRE the server to call back to attacker
   - SSRF vulnerabilities that exfiltrate data via HTTP callbacks need outbound connectivity
   - Reverse shell payloads require the victim to connect OUT to attacker's listener

---

### YOUR TASK

Analyze this CVE and provide accurate tags. Consider:
1. What specific conditions must exist for exploitation?
2. What privileges does the vulnerable service/process typically run with?
3. What does successful exploitation ACTUALLY provide (not worst-case theoretical)?

Output JSON only:"""

    return prompt


def _format_tags_with_descriptions(tags: Dict[str, str]) -> str:
    """Format tags with their descriptions for the prompt."""
    lines = []
    for tag_id, description in tags.items():
        lines.append(f"  - {tag_id}: {description}")
    return "\n".join(lines)
