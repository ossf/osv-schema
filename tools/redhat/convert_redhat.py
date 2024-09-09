#!/usr/bin/env python3
""" Convert a CSAF document to OSV format
    i.e. https://access.redhat.com/security/data/csaf/v2/advisories/2024/rhsa-2024_4546.json
"""
import argparse
import json
import sys
from datetime import datetime

import requests
from jsonschema import validate
from csaf import CSAF
from osv import DATE_FORMAT, OSV, OSVEncoder, SCHEMA_VERSION


class RedHatConverter:
    """
    Class which converts and validates a CSAF string to an OSV string
    """
    SCHEMA = (
        f"https://raw.githubusercontent.com/ossf/osv-schema/v{SCHEMA_VERSION}"
        "/validation/schema.json")
    REQUEST_TIMEOUT = 60

    def __init__(self):
        schema_content = requests.get(self.SCHEMA, timeout=self.REQUEST_TIMEOUT)
        self.osv_schema = schema_content.json()

    def convert(self,
                csaf_content: str,
                modified: str,
                published: str = "") -> tuple[str, str]:
        """
        Converts csaf_content json string into an OSV json string
        returns an OSV ID and the json string content of the OSV file
        the json string content will be empty if no content is applicable
        throws a validation error in the schema doesn't validate correctly.
        The modified value for osv is passed in so it matches what's in all.json
        Raises ValueError is CSAF file can't be parsed
        """
        csaf = CSAF(csaf_content)
        osv = OSV(csaf, modified, published)

        # We convert from an OSV object to a JSON string here in order to use the OSVEncoder
        # Once we OSV json string data we validate it using the OSV schema
        osv_content = json.dumps(osv, cls=OSVEncoder, indent=2)
        osv_data = json.loads(osv_content)
        validate(osv_data, schema=self.osv_schema)

        return osv.id, osv_content


def main():
    """
    Given a Red Hat CSAF document, covert it to OSV. Writes the OSV file to disk at 'osv' by default
    """
    parser = argparse.ArgumentParser(description='CSAF to OSV Converter')
    parser.add_argument("csaf", metavar="FILE", help='CSAF file to process')
    parser.add_argument('--output_directory', dest='out_dir', default="osv")

    args = parser.parse_args()

    with open(args.csaf, "r", encoding="utf-8") as in_f:
        csaf_data = in_f.read()

    converter = RedHatConverter()
    osv_id, osv_data = converter.convert(csaf_data,
                                         datetime.now().strftime(DATE_FORMAT))

    if not osv_data:
        sys.exit(1)

    with open(f"{args.out_dir}/{osv_id}.json", "w", encoding="utf-8") as out_f:
        out_f.write(osv_data)


if __name__ == '__main__':
    main()
