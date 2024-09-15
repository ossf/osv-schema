"""Tests for converting a CSAF document to OSV format"""
import unittest
from datetime import datetime
import json
from redhat_osv.osv import DATE_FORMAT, RedHatConverter


class TestRedHatConverter(unittest.TestCase):
    """Test end-to-end convertion from RedHAt CSAF to OSV format"""

    def test_convert_redhat(self):
        """ Test a single demo CSAF file """
        modified_time = datetime.strptime("2024-09-02T14:30:00",
                                          "%Y-%m-%dT%H:%M:%S")
        csaf_file = "testdata/rhsa-2024_4546.json"
        expected_file = "testdata/RHSA-2024_4546.json"

        with open(csaf_file, "r", encoding="utf-8") as fp:
            csaf_data = fp.read()
        converter = RedHatConverter()
        osv_data = converter.convert(csaf_data,
                                     modified_time.strftime(DATE_FORMAT))

        assert osv_data[0] == "RHSA-2024:4546"
        result_data = json.loads(osv_data[1])

        with open(expected_file, "r", encoding="utf-8") as fp:
            expected_data = json.load(fp)
        assert expected_data == result_data


if __name__ == '__main__':
    unittest.main()
