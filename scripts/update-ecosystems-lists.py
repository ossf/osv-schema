#!/usr/bin/env python3

import json

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


update_json_schema()
