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

import githubkit

_BASE_QUERY = """
query ($cursor: String) {
  securityAdvisories(first: 100 %(query)s after: $cursor) {
    edges {
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
      endCursor
    }
  }
}
"""

def dump(out_dir: str, token: str, query: str):
    """Dumps advisories."""
    count = 0

    github = githubkit.GitHub(token)
    query = _BASE_QUERY % {'query': query}

    for result in github.graphql.paginate(query):
        for edge in result['securityAdvisories']['edges']:
            node = edge['node']
            with open(os.path.join(out_dir, node['ghsaId'] + '.json'),
                      'w') as handle:
                handle.write(json.dumps(node))

            count += 1
            if count % 500 == 0:
                print(f'Up to {count} advisories.')

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
