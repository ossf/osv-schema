"""Test parsing CSAF v2 advisories"""
import unittest

from csaf import Remediation


class CSAFTest(unittest.TestCase):
    """class to handle remediation advice in CSAF data"""

    def test_parse_remediation(self):
        """Test parsing a CSAF Remediation and unpacking cpe and purl data"""
        cpe = "cpe:/a:redhat:rhel_tus:8.4::appstream"
        purl = "pkg:rpm/redhat/buildah@1.19.9-1.module%2Bel8.4.0%2B21078%2Ba96cfbf6?arch=src"
        cpes = {"AppStream-8.4.0.Z.TUS": cpe}
        purls = {"buildah-0:1.19.9-1.module+el8.4.0+21078+a96cfbf6.src": purl}
        result = Remediation(
            "AppStream-8.4.0.Z.TUS:container-tools:3.0:8040020240104111259:c0c392d5"
            ":buildah-0:1.19.9-1.module+el8.4.0+21078+a96cfbf6.src", cpes,
            purls)
        self.assertEqual(result.cpe, cpe)
        self.assertEqual(result.purl, purl)


if __name__ == '__main__':
    unittest.main()
