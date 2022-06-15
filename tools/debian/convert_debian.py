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
import copy
import json
import os
import re
import datetime
from types import SimpleNamespace

import markdownify
import pandas as pd

import first_package_finder

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

  `ecosystem_specific` field in osv
  """

  # Debian release name
  release: str

  # Debian release version number
  version: str

  def __init__(self, release: str, version: str):
    self.release = release
    self.version = version

  # try:
  #         self.version = codename_to_version[self.release]
  #     except KeyError as e:
  #         raise Exception("Debian release name does not exist in map") from e

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
  introduced: str
  versions: [str]

  def __init__(self, release: str, version: str, package: str, fixed: str,
               introduced: str):
    self.ecosystem_specific = DebianSpecificInfo(release, version)
    self.package = package
    self.fixed = fixed
    self.introduced = introduced

  def to_dict(self):
    return {
        'ecosystem_specific':
            self.ecosystem_specific,
        'package': {
            'ecosystem': 'debian:' + self.ecosystem_specific.version,
            'name': self.package
        },
        'ranges': [{
            'type': 'ECOSYSTEM',
            'events': [{
                'introduced': self.introduced
            }, {
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
  modified: str
  affected: [AffectedInfo]
  aliases: [str]
  # Internal use for the script
  preexisting: bool

  def __init__(self, adv_id, summary):
    self.id = adv_id
    self.summary = summary
    self.affected = []
    self.aliases = []
    self.published = ''
    self.details = ''
    self.preexisting = False

  def to_dict(self):
    result = copy.copy(self.__dict__)
    # Remove the preexisting key from the json output since
    # it's only for internal use in the script

    result.pop('preexisting')
    return result

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
                                security_tracker_repo: str,
                                package_data: pd.DataFrame):
  """Parses the security tracker files into the advisories object"""

  with open(
      os.path.join(security_tracker_repo, SECURITY_TRACKER_DSA_PATH),
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

        if advisories[current_advisory].preexisting:
          continue

        # {CVE-XXXX-XXXX CVE-XXXX-XXXX}
        line = line.lstrip()
        if line.startswith('{'):
          advisories[current_advisory].aliases = line.strip('{}').split()
          continue

        if line.startswith('NOTE:'):
          continue

        version_match = VERSION_PATTERN.match(line)
        if not version_match:
          raise ValueError('Invalid version line: ' + line)

        release_name = version_match.group(1)
        package_name = version_match.group(2)
        advisories[current_advisory].affected.append(
            AffectedInfo(
                release_name, package_data.loc[release_name].version,
                package_name, version_match.group(3),
                first_package_finder.get_first_package_version(
                    package_data, package_name, release_name)))
      else:
        if line.strip().startswith('NOTE:'):
          continue

        # New advisory.
        dsa_match = DSA_PATTERN.match(line)
        if not dsa_match:
          raise ValueError('Invalid line: ' + line)

        current_advisory = dsa_match.group(1)
        if not (current_advisory in advisories and
                advisories[current_advisory].preexisting):
          print(current_advisory)
          advisories[current_advisory] = AdvisoryInfo(current_advisory,
                                                      dsa_match.group(2))


def parse_webwml_files(advisories: Advisories, webwml_repo: str):
  """Parses the webwml file into the advisories object"""
  file_path_map = {}

  for root, _, files in os.walk(
      os.path.join(webwml_repo, WEBWML_SECURITY_PATH)):
    for file in files:
      file_path_map[file] = os.path.join(root, file)

  # Add descriptions to advisories from wml files
  for dsa_id, advisory in advisories.items():

    if advisory.preexisting:
      continue
    # remove potential extension (e.g. DSA-12345-2, -2 is the extension)
    mapped_key_no_ext = CAPTURE_DSA_WITH_NO_EXT.findall(dsa_id.lower())[0]
    val_wml = file_path_map.get(mapped_key_no_ext + '.wml')
    val_data = file_path_map.get(mapped_key_no_ext + '.data')

    if not val_wml:
      print('No WML file yet for this: ' + mapped_key_no_ext +
            ', creating partial schema')
      continue

    with open(val_wml, encoding='utf-8') as handle:
      data = handle.read()
      html = WML_DESCRIPTION_PATTERN.findall(data)[0]
      res = markdownify.markdownify(html)
      advisory.details = res

    with open(val_data, encoding='utf-8') as handle:
      data: str = handle.read()
      report_date: str = WML_REPORT_DATE_PATTERN.findall(data)[0]

      # Split by ',' here for the occasional case where there
      # are two dates in the 'publish' field.
      # Multiple dates are caused by major modification later on.
      # This is accounted for with the modified timestamp with git
      # below though, so we don't need to parse them here
      advisory.published = (
          datetime.datetime.strptime(report_date.split(',')[0],
                                     '%Y-%m-%d').isoformat() + 'Z')

    # git_relative_path = pathlib.Path(val_data).relative_to(webwml_repo)
    # git_date_output = subprocess.check_output(
    #     ['git', 'log', '--pretty="%aI"', '-n', '1', git_relative_path],
    #     cwd=webwml_repo)
    #
    # git_date_output_stripped = git_date_output.decode('utf-8').strip('"\n')
    #
    # advisory.modified = datetime.datetime.fromisoformat(
    #     git_date_output_stripped).astimezone(pytz.UTC).isoformat() + 'Z'
    #
    # print(advisory.modified + '    ' + advisory.id)


def write_output(output_dir: str, advisories: Advisories):
  """Writes the advisory dict into individual json files"""
  for dsa_id, advisory in advisories.items():
    if advisory.preexisting:
      continue

    with open(
        os.path.join(output_dir, dsa_id + '.json'), 'w',
        encoding='utf-8') as output_file:
      output_file.write(json.dumps(advisory, default=dumper, indent=2))
      print(
          'Writing: ' + os.path.join(output_dir, dsa_id + '.json'), flush=True)

  print('Complete')


def is_dsa_file(name: str):
  """Check if filename is a DSA output file, e.g. DSA-1234-1.json"""
  return name.startswith('DSA-') and name.endswith('.json')


def load_advisories(json_dir: str, advisories: Advisories):
  """Loads the existing converted advisories"""
  for file in filter(is_dsa_file, os.listdir(json_dir)):
    with open(os.path.join(json_dir, file), encoding='utf-8') as handle:
      # SimpleNamespace loads in the json as a
      # python object instead of a dict
      loaded_advisory: AdvisoryInfo = json.loads(
          handle.read(), object_hook=lambda d: SimpleNamespace(**d))
      if not hasattr(loaded_advisory,
                     'modified') or not loaded_advisory.modified:
        continue

      loaded_advisory.preexisting = True
      advisories[file.removesuffix('.json')] = loaded_advisory


def convert_debian(webwml_repo: str, security_tracker_repo: str,
                   output_dir: str, rebuild: bool, package_data: pd.DataFrame):
  """Convert Debian advisory data into OSV."""
  advisories: Advisories = {}

  if not rebuild:
    load_advisories(output_dir, advisories)

  parse_security_tracker_file(advisories, security_tracker_repo, package_data)
  parse_webwml_files(advisories, webwml_repo)
  write_output(output_dir, advisories)


def main():
  """Main function."""
  parser = argparse.ArgumentParser(description='Debian to OSV converter.')
  parser.add_argument('webwml_repo', help='Debian wml repo')
  parser.add_argument(
      'security_tracker_repo', help='Debian security-tracker repo')
  parser.add_argument(
      '-o', '--output-dir', help='Output directory', required=True)
  # TODO: Potentially add rebuilding as an option if modified date takes too long
  # parser.add_argument(
  #     '--rebuild',
  #     help='Redo every DSA file',
  #     default=False,
  #     action=argparse.BooleanOptionalAction)

  args = parser.parse_args()

  package_data = first_package_finder.load_first_packages()

  convert_debian(args.webwml_repo, args.security_tracker_repo, args.output_dir,
                 True, package_data)


if __name__ == '__main__':
  main()