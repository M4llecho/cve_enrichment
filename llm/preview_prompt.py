#!/usr/bin/env python3
"""
Preview del prompt generato per una CVE specifica.

Uso:
    python -m llm.preview_prompt CVE-2021-44228 --api
    python -m llm.preview_prompt CVE-2021-44228 --ollama
"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from llm.prompts import SYSTEM_PROMPT, build_cve_analysis_prompt
from llm.prompts_api import API_SYSTEM_PROMPT, build_api_analysis_prompt


SAMPLE_CVES = {
    "CVE-2021-44228": {
        "cve_id": "CVE-2021-44228",
        "description": "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases 2.12.2, 2.12.3, and 2.3.1) JNDI features used in configuration, log messages, and parameters do not protect against attacker controlled LDAP and other JNDI related endpoints. An attacker who can control log messages or log message parameters can execute arbitrary code loaded from LDAP servers when message lookup substitution is enabled. From log4j 2.15.0, this behavior has been disabled by default. From version 2.16.0 (along with 2.12.2, 2.12.3, and 2.3.1), this functionality has been completely removed. Note that this vulnerability is specific to log4j-core and does not affect log4net, log4cxx, or other Apache Logging Services projects.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cvss_score": "10.0",
        "cwe_ids": ["CWE-502", "CWE-400", "CWE-20", "CWE-917"],
        "affected_vendors": ["apache"],
        "affected_products": ["log4j"],
        "affected_products_detail": [{"part": "a", "vendor": "apache", "product": "log4j"}],
        "in_kev": True,
        "kev_ransomware_use": True,
        "has_exploit": True,
        "has_nuclei_template": True,
        "has_snort_rule": True,
    },
    "CVE-2024-3400": {
        "cve_id": "CVE-2024-3400",
        "description": "A command injection vulnerability in the GlobalProtect feature of Palo Alto Networks PAN-OS software for specific PAN-OS versions and distinct feature configurations may enable an unauthenticated attacker to execute arbitrary code with root privileges on the firewall.",
        "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
        "cvss_score": "10.0",
        "cwe_ids": ["CWE-77"],
        "affected_vendors": ["paloaltonetworks"],
        "affected_products": ["pan-os"],
        "affected_products_detail": [{"part": "o"}],
        "in_kev": True,
        "kev_ransomware_use": False,
        "has_exploit": True,
    },
}


def main():
    parser = argparse.ArgumentParser(description="Preview prompt per CVE tagging")
    parser.add_argument("cve_id", help="CVE ID (es. CVE-2021-44228)")
    parser.add_argument("--api", action="store_true", help="Mostra prompt ottimizzato per API")
    parser.add_argument("--ollama", action="store_true", help="Mostra prompt per Ollama")
    parser.add_argument("--both", action="store_true", help="Mostra entrambi i prompt")
    args = parser.parse_args()

    cve_data = SAMPLE_CVES.get(args.cve_id.upper())
    if not cve_data:
        print(f"CVE non trovata nei sample. Disponibili: {list(SAMPLE_CVES.keys())}")
        return

    if args.both:
        print("=" * 80)
        print("PROMPT OLLAMA (standard)")
        print("=" * 80)
        print("\n[SYSTEM PROMPT]")
        print(SYSTEM_PROMPT)
        print("\n[USER PROMPT]")
        print(build_cve_analysis_prompt(cve_data))

        print("\n" + "=" * 80)
        print("PROMPT API (ottimizzato)")
        print("=" * 80)
        print("\n[SYSTEM PROMPT]")
        print(API_SYSTEM_PROMPT)
        print("\n[USER PROMPT]")
        print(build_api_analysis_prompt(cve_data))

    elif args.api:
        print("=" * 80)
        print("PROMPT API (ottimizzato)")
        print("=" * 80)
        print("\n[SYSTEM PROMPT]")
        print(API_SYSTEM_PROMPT)
        print("\n[USER PROMPT]")
        print(build_api_analysis_prompt(cve_data))

    else:  # default to ollama
        print("=" * 80)
        print("PROMPT OLLAMA (standard)")
        print("=" * 80)
        print("\n[SYSTEM PROMPT]")
        print(SYSTEM_PROMPT)
        print("\n[USER PROMPT]")
        print(build_cve_analysis_prompt(cve_data))


if __name__ == "__main__":
    main()
