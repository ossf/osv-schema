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
from redhat_osv.osv import DATE_FORMAT, RedHatConverter


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
