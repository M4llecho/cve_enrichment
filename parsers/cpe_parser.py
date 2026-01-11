"""
CPE Parser - extracts vendor/product from CPE URIs.

CPE 2.3 format:
cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other

part: a (application), o (operating system), h (hardware)
"""

import logging
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


class CPEParser:
    """Parser for CPE (Common Platform Enumeration) URIs."""

    # Human-readable names for part codes
    PART_NAMES = {"a": "app", "o": "os", "h": "hw"}

    @staticmethod
    def parse_cpe(cpe_uri: str) -> Optional[Dict[str, str]]:
        """
        Parse a CPE URI and extract components.

        Args:
            cpe_uri: CPE URI string (e.g., cpe:2.3:a:apache:log4j:2.14.0:*:*:*:*:*:*:*)

        Returns:
            Dict with part, vendor, product or None if invalid
        """
        if not cpe_uri or not isinstance(cpe_uri, str):
            return None

        parts = cpe_uri.split(":")
        if len(parts) < 5:
            return None

        # Validate it's a CPE 2.3 format
        if parts[0] != "cpe" or parts[1] != "2.3":
            return None

        return {
            "part": parts[2],
            "vendor": parts[3],
            "product": parts[4],
        }

    @staticmethod
    def extract_affected_products(cpe_list: List[str]) -> Dict[str, any]:
        """
        Extract unique vendors and products from a list of CPE URIs.

        Args:
            cpe_list: List of CPE URI strings

        Returns:
            Dict with:
                - vendors: sorted list of unique vendor names
                - products: sorted list of unique product names
                - details: list of unique {vendor, product, part} dicts
        """
        if not cpe_list:
            return {
                "vendors": [],
                "products": [],
                "details": []
            }

        vendors = set()
        products = set()
        details = []
        seen_details = set()

        for cpe in cpe_list:
            parsed = CPEParser.parse_cpe(cpe)
            if parsed and parsed["vendor"] != "*" and parsed["product"] != "*":
                vendors.add(parsed["vendor"])
                products.add(parsed["product"])

                # Create unique key for deduplication
                key = (parsed["vendor"], parsed["product"], parsed["part"])
                if key not in seen_details:
                    seen_details.add(key)
                    details.append({
                        "vendor": parsed["vendor"],
                        "product": parsed["product"],
                        "part": parsed["part"]
                    })

        return {
            "vendors": sorted(list(vendors)),
            "products": sorted(list(products)),
            "details": details
        }

    @staticmethod
    def get_part_name(part_code: str) -> str:
        """
        Get human-readable name for part code.

        Args:
            part_code: Single letter part code (a, o, h)

        Returns:
            Human-readable name (app, os, hw) or the original code
        """
        return CPEParser.PART_NAMES.get(part_code, part_code)
