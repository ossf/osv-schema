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
import datetime

import markdownify

# import osv
# import osv.ecosystems

WEBWML_SECURITY_PATH = os.path.join('english', 'security')
SECURITY_TRACKER_DSA_PATH = os.path.join('data', 'DSA', 'list')

LEADING_WHITESPACE = re.compile(r'^\s')

# e.g. [25 Apr 2022] DSA-5124-1 ffmpeg - security update
DSA_PATTERN = re.compile(r'\[.*?\]\s*([\w-]+)\s*(.*)')

# e.g. [buster] - xz-utils 5.2.4-1+deb10u1
VERSION_PATTERN = re.compile(r'\[(.*?)\]\s*-\s*([^\s]+)\s*([^\s]+)')

# TODO: Alternative is to use a xml parser here,
#  though the data is not fully compliant with the xml standard
#  It is possible to parse with an html parser however

# e.g. <define-tag moreinfo>\n Some html here \n</define-tag>
WML_DESCRIPTION_PATTERN = re.compile(
    r'<define-tag moreinfo>((?:.|\n)*)</define-tag>', re.MULTILINE)

# e.g. <define-tag report_date>2022-1-04</define-tag>
WML_REPORT_DATE_PATTERN = re.compile(
    r'<define-tag report_date>(.*)</define-tag>')

# e.g. DSA-12345-2, -2 is the extension
CAPTURE_DSA_WITH_NO_EXT = re.compile(r'dsa-\d+')


class DebianSpecificInfo:
    """Specific Debian information, exports to the
    `ecosystem_specific` field in osv"""

    release: str

    def __init__(self, release: str):
        self.release = release

    def to_dict(self):
        return self.__dict__

    def __repr__(self):
        return json.dumps(self, default=dumper)


class AffectedInfo:
    """Debian version info."""

    ecosystem_specific: DebianSpecificInfo
    package: str
    ranges: [str]
    fixed: str
    versions: [str]

    def __init__(self, release: str, package: str, fixed: str):
        self.ecosystem_specific = DebianSpecificInfo(release)
        self.package = package
        self.fixed = fixed

    def to_dict(self):
        return {
            'ecosystem_specific':
                self.ecosystem_specific,
            'package': {
                'ecosystem': 'Debian',
                'name': self.package
            },
            'ranges': [{
                'type': 'ECOSYSTEM',
                'events': [{
                    'fixed': self.fixed
                }]
            }],
        }

    def __repr__(self):
        return json.dumps(self, default=dumper)


class AdvisoryInfo:
    """Debian advisory info."""

    id: str
    summary: str
    details: str
    published: str
    # TODO: Add modified field
    affected: [AffectedInfo]
    aliases: [str]

    def __init__(self, adv_id, summary):
        self.id = adv_id
        self.summary = summary
        self.affected = []
        self.aliases = []
        self.published = ''
        self.details = ''

    def to_dict(self):
        return self.__dict__

    def __repr__(self):
        return json.dumps(self, default=dumper)


Advisories = dict[str, AdvisoryInfo]
"""Type alias for collection of advisory info"""


def dumper(obj):
    try:
        return obj.to_dict()
    except AttributeError:
        return obj.__dict__


def parse_security_tracker_file(advisories: Advisories,
                                security_tracker_repo: str):
    """Parses the security tracker files into the advisories object"""

    with open(os.path.join(security_tracker_repo, SECURITY_TRACKER_DSA_PATH),
              encoding='utf-8') as file_handle:
        current_advisory = None

        # Enumerate advisories + version info from security-tracker.
        for line in file_handle:
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
                    advisories[current_advisory].aliases = line.strip(
                        '{}').split()
                    continue

                if line.startswith('NOTE:'):
                    continue

                version_match = VERSION_PATTERN.match(line)
                if not version_match:
                    raise ValueError('Invalid version line: ' + line)

                advisories[current_advisory].affected.append(
                    AffectedInfo(
                        version_match.group(1),
                        version_match.group(2),
                        version_match.group(3),
                    ))
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


def parse_webwml_files(advisories: Advisories, webwml_repo: str):
    """Parses the webwml file into the advisories object"""
    file_path_map = {}

    for root, _, files in os.walk(
            os.path.join(webwml_repo, WEBWML_SECURITY_PATH)):
        for file in files:
            file_path_map[file] = os.path.join(root, file)

    # Add descriptions to advisories from wml files
    for dsa_id, advisory in advisories.items():

        # remove potential extension (e.g. DSA-12345-2, -2 is the extension)
        mapped_key_no_ext = CAPTURE_DSA_WITH_NO_EXT.findall(dsa_id.lower())[0]
        val_wml = file_path_map.get(mapped_key_no_ext + '.wml')
        val_data = file_path_map.get(mapped_key_no_ext + '.data')

        if not val_wml:
            # TODO: Fill out partial advisory schema
            print('No WML file yet for this: ' + mapped_key_no_ext)
            continue

        with open(val_wml, encoding='utf-8') as handle:
            data = handle.read()
            html = WML_DESCRIPTION_PATTERN.findall(data)[0]
            res = markdownify.markdownify(html)
            advisory.details = res

        with open(val_data, encoding='utf-8') as handle:
            data: str = handle.read()
            report_date: str = WML_REPORT_DATE_PATTERN.findall(data)[0]

            # TODO: Handle multiple dates? What does the
            #  multiple report dates mean
            # if len(report_date.split(',')) > 1:
            #     print(report_date)
            #     print(dsa_id)

            # Split by ',' here for the occasional case where there
            # are two dates in the 'publish' field
            advisory.published = (datetime.datetime.strptime(
                report_date.split(',')[0], '%Y-%m-%d').isoformat() + 'Z')


def write_output(output_dir: str, advisories: Advisories):
    """Writes the advisory dict into individual json files"""
    for dsa_id, advisory in advisories.items():
        with open(os.path.join(output_dir, dsa_id + '.json'),
                  'w',
                  encoding='utf-8') as output_file:
            output_file.write(json.dumps(advisory, default=dumper, indent=2))
            print('Writing: ' + os.path.join(output_dir, dsa_id + '.json'),
                  flush=True)

    print('Complete')


def convert_debian(webwml_repo: str, security_tracker_repo: str,
                   output_dir: str):
    """Convert Debian advisory data into OSV."""
    advisories: Advisories = {}

    parse_security_tracker_file(advisories, security_tracker_repo)
    parse_webwml_files(advisories, webwml_repo)
    write_output(output_dir, advisories)


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
