#!/usr/bin/env python3

import json

MARKDOWN_TABLE_MARKER_START = '<!-- begin auto-generated ecosystems list -->'
MARKDOWN_TABLE_MARKER_END = '<!-- end auto-generated ecosystems list -->'

ecosystems: dict[str, str] = json.loads(open('ecosystems.json').read())


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


update_json_schema()
update_schema_md()
