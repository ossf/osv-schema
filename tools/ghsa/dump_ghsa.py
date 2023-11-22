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
"""GHSA to JSON dumper."""
import argparse
import json
import os

import requests

_BASE_QUERY = """
{
  securityAdvisories(first: 100 %(query)s %(cursor)s) {
    edges { cursor
      node {
        ghsaId
        identifiers {
          value
        }
        references {
          url
        }
        description
        summary
        severity
        cvss {
          score
          vectorString
        }
        cwes(first: 32) {
          nodes {
            cweId
            description
            name
          }
        }
        permalink
        publishedAt
        updatedAt
        withdrawnAt
        vulnerabilities(first: 32) {
          nodes {
            package {
              ecosystem
              name
            }
            firstPatchedVersion {
              identifier
            }
            vulnerableVersionRange
          }
        }
      }
    }
    pageInfo {
      hasNextPage
    }
  }
}
"""


def run_graphql(query: str, token: str):
    """Runs a GraphQL query."""
    response = requests.post(
        'https://api.github.com/graphql',
        json={'query': query},
        headers={'Authorization': 'Bearer ' + token})
    response.raise_for_status()
    return response.json()


def dump(out_dir: str, token: str, query: str):
    """Dumps advisories."""
    count = 0
    cursor_arg = ''

    while True:
        result = run_graphql(_BASE_QUERY % {'cursor':cursor_arg, 'query':query}, token)

        if 'data' not in result:
            print('Got invalid response', result)
            raise Exception('Invalid response')

        for edge in result['data']['securityAdvisories']['edges']:
            node = edge['node']
            with open(os.path.join(out_dir, node['ghsaId'] + '.json'),
                      'w') as handle:
                handle.write(json.dumps(node))

            count += 1
            if count % 500 == 0:
                print(f'Up to {count} advisories.')

            cursor = edge['cursor']
            cursor_arg = f'after: "{cursor}"'

        if not result['data']['securityAdvisories']['pageInfo'].get(
                'hasNextPage'):
            break

    print(f'Dumped {count} advisories.')


def main():
    """Main function."""
    parser = argparse.ArgumentParser(description='GHSA dumper.')
    parser.add_argument('--token', help='GitHub API token', required=True)
    parser.add_argument('--query', help='GitHub Security Advisory Query')
    parser.add_argument('out_dir', help='Output directory')

    args = parser.parse_args()
    dump(args.out_dir, args.token, args.query)


if __name__ == '__main__':
    main()
