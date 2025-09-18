"""Test parsing CSAF v2 advisories"""
import unittest

from redhat_osv.csaf import Remediation


class CSAFTest(unittest.TestCase):
    """class to handle remediation advice in CSAF data"""

    def setUp(self):
        """Set up test data for parameterized tests"""
        self.test_cases = [{
            "name":
            "buildah_module_test",
            "product_id":
            ("AppStream-8.4.0.Z.TUS:container-tools:3.0:8040020240104111259:c0c392d5:"
             "buildah-0:1.19.9-1.module+el8.4.0+21078+a96cfbf6.src"),
            "cpes": {
                "AppStream-8.4.0.Z.TUS": "cpe:/a:redhat:rhel_tus:8.4::appstream"
            },
            "purls": {
                "buildah-0:1.19.9-1.module+el8.4.0+21078+a96cfbf6.src":
                "pkg:rpm/redhat/buildah@1.19.9-1.module%2Bel8.4.0%2B21078%2Ba96cfbf6?arch=src"
            },
            "expected_cpe":
            "cpe:/a:redhat:rhel_tus:8.4::appstream",
            "expected_purl":
            ("pkg:rpm/redhat/buildah@1.19.9-1.module%2Bel8.4.0%2B21078%2Ba96cfbf6?arch=src"
             )
        }, {
            "name":
            "golang_module_test",
            "product_id":
            ("AppStream-8.10.0.Z.MAIN.EUS:go-toolset:rhel8:8100020240701064852:fd72936b:"
             "golang-0:1.21.12-1.module+el8.10.0+20141+6faa2812.src"),
            "cpes": {
                "AppStream-8.10.0.Z.MAIN.EUS":
                "cpe:/a:redhat:rhel_eus:8.10::appstream"
            },
            "purls": {
                "golang-0:1.21.12-1.module+el8.10.0+20141+6faa2812.src":
                "pkg:rpm/redhat/golang@1.21.12-1.module%2Bel8.10.0%2B20141%2B6faa2812?arch=src"
            },
            "expected_cpe":
            "cpe:/a:redhat:rhel_eus:8.10::appstream",
            "expected_purl":
            ("pkg:rpm/redhat/golang@1.21.12-1.module%2Bel8.10.0%2B20141%2B6faa2812?arch=src"
             )
        }, {
            "name":
            "hivex_module_test",
            "product_id":
            ("AppStream-8.10.0.Z.MAIN.EUS:virt:rhel:8100020240701064852:fd72936b:"
             "hivex-0:1.3.18-23.module+el8.10.0+20141+6faa2812.src"),
            "cpes": {
                "AppStream-8.10.0.Z.MAIN.EUS":
                "cpe:/a:redhat:rhel_eus:8.10::appstream"
            },
            "purls": {
                "hivex-0:1.3.18-23.module+el8.10.0+20141+6faa2812.src":
                "pkg:rpm/redhat/hivex@1.3.18-23.module%2Bel8.10.0%2B20141%2B6faa2812?arch=src"
            },
            "expected_cpe":
            "cpe:/a:redhat:rhel_eus:8.10::appstream",
            "expected_purl":
            ("pkg:rpm/redhat/hivex@1.3.18-23.module%2Bel8.10.0%2B20141%2B6faa2812?arch=src"
             )
        }, {
            "name":
            "simple_package_test",
            "product_id":
            "BaseOS-8.10.0.Z.MAIN.EUS:kernel-0:4.18.0-553.16.1.el8_10.src",
            "cpes": {
                "BaseOS-8.10.0.Z.MAIN.EUS":
                "cpe:/o:redhat:rhel_eus:8.10::baseos"
            },
            "purls": {
                "kernel-0:4.18.0-553.16.1.el8_10.src":
                "pkg:rpm/redhat/kernel@4.18.0-553.16.1.el8_10?arch=src"
            },
            "expected_cpe":
            "cpe:/o:redhat:rhel_eus:8.10::baseos",
            "expected_purl":
            ("pkg:rpm/redhat/kernel@4.18.0-553.16.1.el8_10?arch=src")
        }, {
            "name":
            "slof_csaf_test",
            "product_id":
            "CRB-8.10.0.Z.MAIN.EUS:SLOF-20210217-2.module+el8.10.0+20141+6faa2812"
            ".src.rpm-virt-devel:rhel",
            "cpes": {
                "CRB-8.10.0.Z.MAIN.EUS": "cpe:/a:redhat:enterprise_linux:8::crb"
            },
            "purls": {
                "SLOF-20210217-2.module+el8.10.0+20141+6faa2812.src.rpm-virt-devel:rhel":
                "pkg:rpm/redhat/SLOF@20210217-2.module%2Bel8.10.0%2B20141%2B6faa2812?arch=src&"
                "rpmmod=virt-devel:rhel:8100020240704072441:489197e6"
            },
            "expected_cpe":
            "cpe:/a:redhat:enterprise_linux:8::crb",
            "expected_purl":
            "pkg:rpm/redhat/SLOF@20210217-2.module%2Bel8.10.0%2B20141%2B"
            "6faa2812?arch=src&rpmmod=virt-devel:rhel:8100020240704072441:489197e6"
        }]

    def test_parse_remediation_parameterized(self):
        """Test parsing CSAF Remediations with multiple test cases"""
        for test_case in self.test_cases:
            with self.subTest(test_case=test_case["name"]):
                result = Remediation(test_case["product_id"], test_case["cpes"],
                                     test_case["purls"])
                self.assertEqual(result.cpe, test_case["expected_cpe"],
                                 f"CPE mismatch for {test_case['name']}")
                self.assertEqual(result.purl, test_case["expected_purl"],
                                 f"PURL mismatch for {test_case['name']}")


if __name__ == '__main__':
    unittest.main()
