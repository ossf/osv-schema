#!/usr/bin/env python3

import json

MARKDOWN_TABLE_MARKER_START = '<!-- begin auto-generated ecosystems list -->'
MARKDOWN_TABLE_MARKER_END = '<!-- end auto-generated ecosystems list -->'

# ensure that the ecosystems are sorted alphabetically and don't have extra whitespace
ecosystems: dict[str, str] = {
  k: v.strip() for k, v in sorted(
    json.loads(open('ecosystems.json').read()).items(),
    key=lambda item: item[0].casefold()
  )
}

# write back to the json file in case there were any changes
open('ecosystems.json', 'w').write(json.dumps(ecosystems, indent=2) + '\n')


def update_json_schema():
  """
  Updates references to ecosystems defined in the OSV JSON schema
  :return:
  """
  schema = json.loads(open('validation/schema.json').read())

  names = ecosystems.keys()
  pattern = ""

  for name in names:
    pattern += name.replace(".", "\\.")
    pattern += "|"

  # this is a special "ecosystem" name
  pattern += "GIT"

  schema['$defs']['ecosystemName']['enum'] = list(names)
  schema['$defs']['ecosystemWithSuffix']['pattern'] = f'^({pattern})(:.+)?$'

  open('validation/schema.json', 'w').write(json.dumps(schema, indent=2) + '\n')


def generate_ecosystems_markdown_table() -> str:
  """
  Generates a Markdown table of supported ecosystems with descriptions
  :return:
  """
  table = '| Ecosystem | Description |\n'
  table += '|-----------|-------------|\n'

  for name, description in ecosystems.items():
    table += f'| `{name}` | {description} |\n'

  return table


def update_schema_md():
  """
  Updates the schema.md file with the list of ecosystems
  :return:
  """
  md = open('docs/schema.md').read()

  table_start_index = md.index(MARKDOWN_TABLE_MARKER_START)
  table_end_index = md.index(MARKDOWN_TABLE_MARKER_END)

  assert table_start_index < table_end_index, "Table start index must be before table end index"

  table = generate_ecosystems_markdown_table()
  table += '| Your ecosystem here. | [Send us a PR](https://github.com/ossf/osv-schema/compare). |\n'

  md = '{0}{1}\n\n{2}\n{3}{4}'.format(
    md[:table_start_index],
    MARKDOWN_TABLE_MARKER_START,
    table,
    MARKDOWN_TABLE_MARKER_END,
    md[table_end_index + len(MARKDOWN_TABLE_MARKER_END):]
  )

  open('docs/schema.md', 'w').write(md)


def convert_to_go_constant_name(name: str) -> str:
  """
  Converts the "human" name of an ecosystem to a Go constant name, mostly
  by removing spaces and dashes and converting to PascalCase.

  Some ecosystems have special cases, like "crates.io" which is converted to "CratesIO".

  :param name:
  :return:
  """
  if name == 'crates.io':
    return 'EcosystemCratesIO'

  if name == 'npm':
    return 'EcosystemNPM'

  name = name[0].upper() + name[1:]
  name = name.replace('-', '').replace(' ', '')

  return f'Ecosystem{name}'


def generate_ecosystems_go_constants() -> str:
  """
  Generates a list of Go constants, with a constant per ecosystem
  :return:
  """

  constants = list(map(lambda x: (convert_to_go_constant_name(x), x), ecosystems.keys()))
  longest = max(map(lambda x: len(x[0]), constants))

  code = 'const (\n'
  for constant, name in constants:
    code += f'\t{constant.ljust(longest)} Ecosystem = "{name}"\n'
  code += ')\n'

  return code


def update_go_constants():
  """
  Updates the Go constants with the list of ecosystems
  :return:
  """
  go = open('bindings/go/osvschema/constants.go').read()

  ecosystem_constants_start = go.index('type Ecosystem string\n\nconst (\n')
  ecosystems_constants_end = go.index(')', ecosystem_constants_start)

  go = '{0}{1}\n\n{2}{3}'.format(
    go[:ecosystem_constants_start],
    'type Ecosystem string',
    generate_ecosystems_go_constants(),
    go[ecosystems_constants_end + 2:]
  )

  open('bindings/go/osvschema/constants.go', 'w').write(go)


update_go_constants()
update_json_schema()
update_schema_md()
