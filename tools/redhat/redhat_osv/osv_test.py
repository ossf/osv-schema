"""Test Intermediate OSV object creation"""
import unittest

from redhat_osv.csaf import CSAF
from redhat_osv.osv import OSV, Event


class ScoreTest(unittest.TestCase):
    """Tests OSV vulnerability scores"""

    test_csaf_files = [
        "rhsa-2003_315.json", "rhsa-2015_0008.json"
    ]

    def test_missing_cvss_v3(self):
        """Test parsing a CSAF file with missing CVSSv3 score"""
        for test_csaf_file in self.test_csaf_files:
            csaf_file = f"testdata/CSAF/{test_csaf_file}"
            with open(csaf_file, "r", encoding="utf-8") as fp:
                csaf_data = fp.read()
            csaf = CSAF(csaf_data)
            with self.subTest(csaf_file):
                assert csaf
                assert len(csaf.vulnerabilities) == 1
                assert not csaf.vulnerabilities[0].cvss_v3_base_score
                for vuln in csaf.vulnerabilities:
                    for remediation in vuln.remediations:
                        assert "@" in remediation.purl

                # See https://github.com/ossf/osv-schema/pull/308#issuecomment-2456061864
                osv = OSV(csaf, "test_date")
                assert not hasattr(osv, "severity")
                for affected in osv.affected:
                    assert "@" not in affected.package.purl


class EventTest(unittest.TestCase):
    """ Tests OSV affected range events"""

    def test_init_event(self):
        """Test parsing various Events"""
        event = Event("introduced")
        assert event.event_type == "introduced"
        assert event.version == "0"

        event = Event("fixed", "1")
        assert event.event_type == "fixed"
        assert event.version == "1"

        with self.assertRaises(ValueError):
            Event("test")


if __name__ == '__main__':
    unittest.main()
