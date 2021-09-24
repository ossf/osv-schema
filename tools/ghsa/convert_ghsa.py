# Copyright 2021 OSV Schema Authors
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
"""GHSA to OSV converter."""
import argparse
import json
import os
import re
import traceback
from typing import Any, Dict, Optional

# GHSA ecosystem -> OSV ecosystem.
ECOSYSTEM_MAP = {
    'NPM': 'npm',
    'GO': 'Go',
    'MAVEN': 'Maven',
    'PIP': 'PyPI',
    'RUBYGEMS': 'RubyGems',
    'NUGET': 'NuGet',
    'COMPOSER': 'Packagist',
    'RUST': 'crates.io',
}

NAME_NORMALIZER = {
    # Per https://www.python.org/dev/peps/pep-0503/#normalized-names.
    'PyPI': lambda name: re.sub(r'[-_.]+', '-', name).lower()
}

SEMVER_ECOSYSTEMS = {
    'npm',
    'Go',
}


class GhsaVersionSpec:
    """GHSA version spec."""
    operator: str
    version: str

    def __init__(self, operator: str, version: str):
        self.operator = operator
        self.version = version


class GhsaRange:
    """GHSA Range."""
    lower: Optional[GhsaVersionSpec] = None
    upper: Optional[GhsaVersionSpec] = None
    exact: Optional[GhsaVersionSpec] = None


def parse_ghsa_range(ghsa_range: str):
    """Parses a GHSA version range."""
    # GHSA range format is described at:
    # https://docs.github.com/en/graphql/reference/objects#securityvulnerability
    # "= 0.2.0" denotes a single vulnerable version.
    # "<= 1.0.8" denotes a version range up to and including the specified
    # version
    # "< 0.1.11" denotes a version range up to, but excluding, the specified
    # version
    # ">= 4.3.0, < 4.3.5" denotes a version range with a known minimum and
    # maximum version.
    # ">= 0.0.1" denotes a version range with a known minimum, but no known
    # maximum.
    # (Undocumented) ">" is also a valid operator.
    parts = [part.strip() for part in ghsa_range.split(',')]

    parsed_range = GhsaRange()
    for part in parts:
        try:
            operator, version = part.split()
        except ValueError as exc:
            raise ValueError('Failed to parse GHSA range: '
                             f'"{ghsa_range}"') from exc

        spec = GhsaVersionSpec(operator, version)

        if operator == '=':
            parsed_range.exact = spec
        elif operator in ('>=', '>'):
            parsed_range.lower = spec
        elif operator in ('<=', '<'):
            parsed_range.upper = spec
        else:
            raise ValueError(f'Unknown operator "{operator}"')

    if parsed_range.exact and (parsed_range.lower or parsed_range.upper):
        raise ValueError('Range with both exact and lower/upper bounds: '
                         f'"{ghsa_range}"')

    return parsed_range


def convert_file(input_path: str, output_path: str):
    """Converts `input_path` from GHSA JSON and output OSV JSON at
    `output_path`."""
    with open(input_path) as handle:
        ghsa = json.load(handle)

    osv = convert(ghsa)
    with open(output_path, 'w') as handle:
        handle.write(json.dumps(osv, indent=2))


def convert_reference(reference: Dict[str, str]):
    """Converts a GHSA reference to an OSV reference."""
    ref_type = 'WEB'

    if 'github.com/advisories/' in reference['url']:
        ref_type = 'ADVISORY'

    if 'nvd.nist.gov/vuln/detail/' in reference['url']:
        ref_type = 'ADVISORY'

    return {
        'type': ref_type,
        'url': reference['url'],
    }


def convert(ghsa: Dict[str, Any]):
    """Converts a GHSA entry to an OSV entry."""
    osv = {
        'id':
        ghsa['ghsaId'],
        'aliases': [
            val['value'] for val in ghsa['identifiers']
            if val['value'] != ghsa['ghsaId']
        ],
        'published':
        ghsa['publishedAt'],
        'modified':
        ghsa['updatedAt'],
    }

    # Split up the dict assignments to preserve order of date related fields.
    withdrawn = ghsa.get('withdrawnAt')
    if withdrawn:
        osv['withdrawn'] = withdrawn

    osv.update({
        'summary':
        ghsa['summary'],
        'details':
        ghsa['description'],
        'references': [convert_reference(ref) for ref in ghsa['references']]
    })

    osv['affected'] = get_affected(ghsa)
    return osv


def get_affected(ghsa: Dict[str, Any]):
    """Converts the GHSA entry into an OSV "affected" entry."""
    package_to_vulns = {}

    # Group vulnerabilities by (ecosystem, package).
    for vuln in ghsa.get('vulnerabilities', []).get('nodes', []):
        package = vuln['package']
        mapped_ecosystem = ECOSYSTEM_MAP[package['ecosystem']]
        package_to_vulns.setdefault((mapped_ecosystem, package['name']),
                                    []).append(vuln)

    cvss = ghsa.get('cvss', {})
    cwes = ghsa.get('cwes', {}).get('nodes', [])

    # Convert the grouped vulnerabilities in OSV range structures.
    affected = []
    for (ecosystem, name), vulns in package_to_vulns.items():
        if ecosystem in NAME_NORMALIZER:
            name = NAME_NORMALIZER[ecosystem](name)

        current = {
            'package': {
                'ecosystem': ecosystem,
                'name': name,
            },
            'ranges': [],
            'versions': [],
            'database_specific': {
                # Attribution.
                'ghsa': ghsa['permalink'],
                'cvss': cvss,
                'cwes': cwes,
            }
        }
        affected.append(current)

        current_range = {
            'type': 'SEMVER' if ecosystem in SEMVER_ECOSYSTEMS else 'ECOSYSTEM',
            'events': [],
        }
        current_events = current_range['events']

        affects_all_prior = False

        for vuln in vulns:
            first_patched = vuln.get('firstPatchedVersion')
            if first_patched:
                first_patched = first_patched.get('identifier')

            ghsa_range = parse_ghsa_range(vuln.get('vulnerableVersionRange'))

            if ghsa_range.exact:
                if first_patched:
                    # A patch is specified, so convert it to an OSV range.
                    current_events.extend([
                        {
                            'introduced': ghsa_range.exact.version
                        },
                        {
                            'fixed': first_patched
                        },
                    ])
                else:
                    # No patch, so just add it to the explicit versions array.
                    current['versions'].append(ghsa_range.exact.version)

                continue

            if ghsa_range.lower:
                if ghsa_range.lower.operator == '>=':
                    current_events.append(
                        {'introduced': ghsa_range.lower.version})
                elif ghsa_range.lower.operator == '>':
                    # TODO: Support this rare case.
                    # OSV only support ranges with >= lower_bound, so we'll need to
                    # figure out the next available version.
                    raise ValueError('> is not supported yet')
            else:
                affects_all_prior = True

            if ghsa_range.upper:
                if ghsa_range.upper.operator == '<=':
                    if first_patched:
                        current_events.append({'fixed': first_patched})

                    # OSV ranges only allow < and not <=. If there is no patch, then all
                    # versions from beginning of time are affected.
                elif ghsa_range.upper.operator == '<':
                    current_events.append({'fixed': ghsa_range.upper.version})
            elif first_patched:
                # No upper bound set in the range, check the firstPatchedVersion.
                current_events.append({'fixed': first_patched})

        if affects_all_prior:
            current_events.insert(0, {'introduced': '0'})

        if current_events:
            # Only add the range if there is at least one event.
            current['ranges'].append(current_range)

    return affected


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='GHSA to OSV converter.')
    parser.add_argument('input_files', help='Input files', nargs='+')
    parser.add_argument('-o',
                        '--output-dir',
                        help='Output directory',
                        required=True)

    args = parser.parse_args()
    for input_path in args.input_files:
        try:
            convert_file(
                input_path,
                os.path.join(args.output_dir, os.path.basename(input_path)))
        except Exception:
            print('Failed to convert', input_path)
            traceback.print_exc()


if __name__ == '__main__':
    main()
