# Copyright 2022 OSV Schema Authors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""Debian to OSV converter."""
import argparse
import json
import os
import re
import traceback
from typing import Any, Dict, Optional
import xml.etree.ElementTree as ET

import osv
import osv.ecosystems

WEBWML_SECURITY_PATH = os.path.join('english', 'security')
SECURITY_TRACKER_DSA_PATH = os.path.join('data', 'DSA', 'list')

LEADING_WHITESPACE = re.compile(r'^\s')

# e.g. [25 Apr 2022] DSA-5124-1 ffmpeg - security update
DSA_PATTERN = re.compile(r'\[.*?\]\s*([\w-]+)\s*(.*)')

# e.g. [buster] - xz-utils 5.2.4-1+deb10u1
VERSION_PATTERN = re.compile(r'\[(.*?)\]\s*-\s*([^\s]+)\s*([^\s]+)')


class VersionInfo:
    """Debian version info."""
    release: str
    package: str
    fixed: str

    def __init__(self, release: str, package: str, fixed: str):
        self.release = release
        self.package = package
        self.fixed = fixed

    def __repr__(self):
        return str({
            'release': self.release,
            'package': self.package,
            'fixed': self.fixed,
        })


class AdvisoryInfo:
    """Debian advisory info."""
    id: str
    summary: str
    versions: [VersionInfo]
    cves: [str]

    def __init__(self, id, summary):
        self.id = id
        self.summary = summary
        self.versions = []
        self.cves = []

    def __repr__(self):
        return str({
            'id': self.id,
            'summary': self.summary,
            'versions': self.versions,
            'cves': self.cves,
        })


def convert_debian(webwml_repo: str, security_tracker_repo: str,
                   output_dir: str):
    """Convert Debian advisory data into OSV."""
    advisories = {}
    current_advisory = None

    # Enumerate advisories + version info from security-tracker.
    with open(os.path.join(security_tracker_repo,
                           SECURITY_TRACKER_DSA_PATH)) as handle:
        for line in handle:
            line = line.rstrip()
            if not line:
                continue

            if LEADING_WHITESPACE.match(line):
                # Within current advisory.
                if not current_advisory:
                    raise ValueError('Unexpected tab.')

                # {CVE-XXXX-XXXX CVE-XXXX-XXXX}
                line = line.lstrip()
                if line.startswith('{'):
                    advisories[current_advisory].cves = line.strip('{}').split()
                    continue

                if line.startswith('NOTE:'):
                    continue

                version_match = VERSION_PATTERN.match(line)
                if not version_match:
                    raise ValueError('Invalid version line: ' + line)

                advisories[current_advisory].versions.append(
                    VersionInfo(version_match.group(1), version_match.group(2),
                                version_match.group(3)))
            else:
                if line.strip().startswith('NOTE:'):
                    continue

                # New advisory.
                dsa_match = DSA_PATTERN.match(line)
                if not dsa_match:
                    raise ValueError('Invalid line: ' + line)

                current_advisory = dsa_match.group(1)
                advisories[current_advisory] = AdvisoryInfo(
                    current_advisory, dsa_match.group(2))

    print(advisories)


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='Debian to OSV converter.')
    parser.add_argument('webwml_repo', help='Debian wml repo')
    parser.add_argument('security_tracker_repo',
                        help='Debian security-tracker repo')
    parser.add_argument('-o',
                        '--output-dir',
                        help='Output directory',
                        required=True)
    args = parser.parse_args()

    convert_debian(args.webwml_repo, args.security_tracker_repo,
                   args.output_dir)


if __name__ == '__main__':
    main()
