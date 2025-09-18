"""Test Intermediate OSV object creation"""
import unittest

from redhat_osv.csaf import CSAF
from redhat_osv.osv import OSV, Event


class ScoreTest(unittest.TestCase):
    """Tests OSV vulnerability scores"""

    test_csaf_files = ["rhsa-2003_315.json", "rhsa-2015_0008.json"]

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

    def test_events_from_csaf_files(self):
        """Test that events from CSAF files have expected versions"""
        test_csaf_files = ["rhsa-2024_6220.json", "rhsa-2024_4420.json"]

        for test_csaf_file in test_csaf_files:
            csaf_file = f"testdata/CSAF/{test_csaf_file}"
            with open(csaf_file, "r", encoding="utf-8") as fp:
                csaf_data = fp.read()
            csaf = CSAF(csaf_data)
            osv = OSV(csaf, "2024-01-01T00:00:00Z")

            with self.subTest(csaf_file):
                # Verify that we have affected packages
                assert len(osv.affected) > 0

                # Check each affected package's ranges and events
                for affected in osv.affected:
                    assert len(affected.ranges) > 0

                    for range_obj in affected.ranges:
                        assert len(
                            range_obj.events
                        ) == 2  # Should have introduced and fixed events

                        # First event should be "introduced" with version "0"
                        introduced_event = range_obj.events[0]
                        assert introduced_event.event_type == "introduced"
                        assert introduced_event.version == "0"

                        # Second event should be "fixed" with a non-empty version
                        fixed_event = range_obj.events[1]
                        assert fixed_event.event_type == "fixed"
                        assert fixed_event.version != ""
                        assert fixed_event.version != "0"

                        # Red Hat versions should be in EVRA format or similar
                        # Examples: "0:5.4.1-1.module+el8.5.0+10613+59a13ec4"
                        #          "23.module+el8.9.0+18724+20190c23.x86_64"
                        # They should contain either ":" (epoch) 
                        assert ":" in fixed_event.version

                        # Version should not be just a number
                        assert not fixed_event.version.isdigit()

                        # Ensure we don't get module names as versions
                        assert not fixed_event.version.endswith(":rhel")
                        assert "virt:" not in fixed_event.version


if __name__ == '__main__':
    unittest.main()
