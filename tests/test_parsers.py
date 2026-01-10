"""
Unit tests for parsers.
These tests use mock data to verify parser logic.
"""

import unittest
import sys
import os
import tempfile
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))


class TestCWEParser(unittest.TestCase):
    """Tests for CWE Parser."""

    def setUp(self):
        """Create a temporary CWE XML file."""
        self.temp_dir = tempfile.mkdtemp()
        self.cwe_xml = Path(self.temp_dir) / "cwe_test.xml"

        cwe_content = '''<?xml version="1.0" encoding="UTF-8"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7"
                  Name="CWE"
                  Version="4.12">
    <Weaknesses>
        <Weakness ID="79" Name="Improper Neutralization of Input During Web Page Generation">
            <Description>The application does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output.</Description>
            <Related_Attack_Patterns>
                <Related_Attack_Pattern CAPEC_ID="86"/>
                <Related_Attack_Pattern CAPEC_ID="198"/>
            </Related_Attack_Patterns>
        </Weakness>
        <Weakness ID="502" Name="Deserialization of Untrusted Data">
            <Description>The application deserializes untrusted data without verification.</Description>
            <Related_Attack_Patterns>
                <Related_Attack_Pattern CAPEC_ID="586"/>
            </Related_Attack_Patterns>
        </Weakness>
    </Weaknesses>
</Weakness_Catalog>'''

        with open(self.cwe_xml, "w") as f:
            f.write(cwe_content)

    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_cwe_details_extraction(self):
        """Test CWE details are extracted correctly."""
        try:
            from parsers.cwe_parser import CWEParser
        except ImportError as e:
            self.skipTest(f"Skipping due to missing dependency: {e}")

        parser = CWEParser(self.cwe_xml)
        details = parser.get_cwe_details()

        self.assertEqual(len(details), 2)

        cwe_79 = next(d for d in details if d["cwe_id"] == "CWE-79")
        self.assertEqual(cwe_79["cwe_name"], "Improper Neutralization of Input During Web Page Generation")
        self.assertIn("neutralize", cwe_79["description"])

        cwe_502 = next(d for d in details if d["cwe_id"] == "CWE-502")
        self.assertEqual(cwe_502["cwe_name"], "Deserialization of Untrusted Data")

    def test_cwe_capec_mappings(self):
        """Test CWE to CAPEC mappings are extracted correctly."""
        try:
            from parsers.cwe_parser import CWEParser
        except ImportError as e:
            self.skipTest(f"Skipping due to missing dependency: {e}")

        parser = CWEParser(self.cwe_xml)
        mappings = parser.get_cwe_capec_mappings()

        self.assertEqual(len(mappings), 3)

        # Check CWE-79 has two CAPEC mappings
        cwe_79_mappings = [m for m in mappings if m[0] == "CWE-79"]
        self.assertEqual(len(cwe_79_mappings), 2)
        capec_ids = [m[1] for m in cwe_79_mappings]
        self.assertIn("CAPEC-86", capec_ids)
        self.assertIn("CAPEC-198", capec_ids)

        # Check CWE-502 has one CAPEC mapping
        cwe_502_mappings = [m for m in mappings if m[0] == "CWE-502"]
        self.assertEqual(len(cwe_502_mappings), 1)
        self.assertEqual(cwe_502_mappings[0][1], "CAPEC-586")


class TestCAPECParser(unittest.TestCase):
    """Tests for CAPEC Parser."""

    def setUp(self):
        """Create a temporary CAPEC XML file."""
        self.temp_dir = tempfile.mkdtemp()
        self.capec_xml = Path(self.temp_dir) / "capec_test.xml"

        capec_content = '''<?xml version="1.0" encoding="UTF-8"?>
<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3"
                        Name="CAPEC"
                        Version="3.9">
    <Attack_Patterns>
        <Attack_Pattern ID="86" Name="XSS Through HTTP Headers">
            <Description>An adversary exploits the trust a site has in HTTP headers.</Description>
            <Taxonomy_Mappings>
                <Taxonomy_Mapping Taxonomy_Name="ATTACK">
                    <Entry_ID>T1059</Entry_ID>
                    <Entry_Name>Command and Scripting Interpreter</Entry_Name>
                </Taxonomy_Mapping>
            </Taxonomy_Mappings>
        </Attack_Pattern>
        <Attack_Pattern ID="586" Name="Object Injection">
            <Description>An adversary attempts to leverage code in order to exploit object injection.</Description>
            <Taxonomy_Mappings>
                <Taxonomy_Mapping Taxonomy_Name="ATTACK">
                    <Entry_ID>T1190</Entry_ID>
                    <Entry_Name>Exploit Public-Facing Application</Entry_Name>
                </Taxonomy_Mapping>
                <Taxonomy_Mapping Taxonomy_Name="ATTACK">
                    <Entry_ID>T1059</Entry_ID>
                    <Entry_Name>Command and Scripting Interpreter</Entry_Name>
                </Taxonomy_Mapping>
            </Taxonomy_Mappings>
        </Attack_Pattern>
    </Attack_Patterns>
</Attack_Pattern_Catalog>'''

        with open(self.capec_xml, "w") as f:
            f.write(capec_content)

    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_capec_technique_mappings(self):
        """Test CAPEC to Technique mappings are extracted correctly."""
        try:
            from parsers.capec_parser import CAPECParser
        except ImportError as e:
            self.skipTest(f"Skipping due to missing dependency: {e}")

        parser = CAPECParser(self.capec_xml)
        mappings = parser.get_capec_technique_mappings()

        # Should have 3 unique mappings
        self.assertEqual(len(mappings), 3)

        # Check CAPEC-86 mapping
        capec_86 = [m for m in mappings if m[0] == "CAPEC-86"]
        self.assertEqual(len(capec_86), 1)
        self.assertEqual(capec_86[0][1], "T1059")
        self.assertEqual(capec_86[0][2], "Command and Scripting Interpreter")

        # Check CAPEC-586 mappings
        capec_586 = [m for m in mappings if m[0] == "CAPEC-586"]
        self.assertEqual(len(capec_586), 2)
        technique_ids = [m[1] for m in capec_586]
        self.assertIn("T1190", technique_ids)
        self.assertIn("T1059", technique_ids)


class TestATTACKParser(unittest.TestCase):
    """Tests for ATT&CK Parser."""

    def setUp(self):
        """Create a temporary ATT&CK JSON file."""
        self.temp_dir = tempfile.mkdtemp()
        self.attack_json = Path(self.temp_dir) / "attack_test.json"

        import json
        attack_data = {
            "objects": [
                {
                    "type": "x-mitre-tactic",
                    "name": "Execution",
                    "x_mitre_shortname": "execution"
                },
                {
                    "type": "x-mitre-tactic",
                    "name": "Initial Access",
                    "x_mitre_shortname": "initial-access"
                },
                {
                    "type": "attack-pattern",
                    "name": "Command and Scripting Interpreter",
                    "description": "Adversaries may abuse command and script interpreters.",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1059"}
                    ],
                    "kill_chain_phases": [
                        {"kill_chain_name": "mitre-attack", "phase_name": "execution"}
                    ]
                },
                {
                    "type": "attack-pattern",
                    "name": "Exploit Public-Facing Application",
                    "description": "Adversaries may attempt to exploit vulnerabilities.",
                    "external_references": [
                        {"source_name": "mitre-attack", "external_id": "T1190"}
                    ],
                    "kill_chain_phases": [
                        {"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}
                    ]
                }
            ]
        }

        with open(self.attack_json, "w") as f:
            json.dump(attack_data, f)

    def tearDown(self):
        """Clean up temporary files."""
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)

    def test_technique_tactic_mappings(self):
        """Test Technique to Tactic mappings are extracted correctly."""
        try:
            from parsers.attack_parser import ATTACKParser
        except ImportError:
            self.skipTest("Skipping due to missing dependency")

        parser = ATTACKParser(self.attack_json)
        mappings = parser.get_technique_tactic_mappings()

        self.assertEqual(len(mappings), 2)

        # Check T1059 -> Execution
        t1059 = next(m for m in mappings if m[0] == "T1059")
        self.assertEqual(t1059[1], "execution")
        self.assertEqual(t1059[2], "Execution")

        # Check T1190 -> Initial Access
        t1190 = next(m for m in mappings if m[0] == "T1190")
        self.assertEqual(t1190[1], "initial-access")
        self.assertEqual(t1190[2], "Initial Access")

    def test_get_technique_name(self):
        """Test getting technique name by ID."""
        try:
            from parsers.attack_parser import ATTACKParser
        except ImportError:
            self.skipTest("Skipping due to missing dependency")

        parser = ATTACKParser(self.attack_json)

        name = parser.get_technique_name("T1059")
        self.assertEqual(name, "Command and Scripting Interpreter")

        name = parser.get_technique_name("T1190")
        self.assertEqual(name, "Exploit Public-Facing Application")

        name = parser.get_technique_name("T9999")
        self.assertIsNone(name)


class TestNVDParser(unittest.TestCase):
    """Tests for NVD CVE parsing."""

    def test_cve_parsing(self):
        """Test CVE data parsing from NVD format."""
        try:
            from downloaders.nvd import NVDDownloader
        except ImportError as e:
            self.skipTest(f"Skipping due to missing dependency: {e}")

        downloader = NVDDownloader()

        # Mock NVD CVE data
        cve_data = {
            "id": "CVE-2021-44228",
            "descriptions": [
                {"lang": "en", "value": "Apache Log4j2 vulnerability allows RCE."}
            ],
            "published": "2021-12-10T10:15:00.000",
            "lastModified": "2023-04-03T20:15:00.000",
            "metrics": {
                "cvssMetricV31": [{
                    "cvssData": {
                        "baseScore": 10.0,
                        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                        "baseSeverity": "CRITICAL"
                    }
                }]
            },
            "weaknesses": [{
                "description": [{"value": "CWE-502"}]
            }]
        }

        parsed = downloader._parse_cve(cve_data)

        self.assertEqual(parsed["cve_id"], "CVE-2021-44228")
        self.assertIn("Log4j2", parsed["description"])
        self.assertEqual(parsed["cvss_v3_score"], 10.0)
        self.assertEqual(parsed["cvss_severity"], "CRITICAL")
        self.assertEqual(parsed["cwe_id"], "CWE-502")


if __name__ == "__main__":
    unittest.main()
