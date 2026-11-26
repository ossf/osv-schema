#!/usr/bin/env python3

import json
import os
import re
from html.parser import HTMLParser


class UnexpectedTagError(Exception):
  pass


class HTMLValidator(HTMLParser):
  def __init__(self) -> None:
    super().__init__()

    self.__tags: list[str] = []

  def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
    self.__tags.append(tag)

  def handle_endtag(self, tag: str) -> None:
    last_tag = self.__tags.pop()
    if last_tag != tag:
      raise UnexpectedTagError(last_tag)


def extract_schema_table() -> tuple[str, int]:
  raw_table = ''
  index = -1

  with open('docs/schema.md') as f:
    for i, line in enumerate(f.readlines()):
      if line == '<table>\n':
        index = i + 1
        raw_table += line
      if raw_table != '':
        raw_table += line
      if line == '</table>\n':
        break
  return raw_table, index


table, starting_line = extract_schema_table()

validator = HTMLValidator()

try:
  validator.feed(table)
except UnexpectedTagError as e:
  if 'CI' in os.environ:
    print(
      f'::error file=docs/schema.md,line={starting_line}::unexpected {e} tag in table - ensure that the tags are properly paired'
    )
  print(
    f'unexpected {e} tag in docs/schema.md databases table - ensure that the tags are properly paired'
  )
  exit(1)


# prefixes that are in the schema but intentionally have no row in the table
# yet, e.g. because the database hasn't been published
PREFIXES_WITHOUT_ROW = {
  'FreeBSD',  # https://github.com/ossf/osv-schema/pull/448
}


def table_prefixes(raw_table: str) -> set[str]:
  prefixes = set()
  for cell in re.findall(r'<tr>\s*<td>(.*?)</td>', raw_table, re.S):
    prefixes.update(re.findall(r'<code>(.*?)</code>', cell))
  return prefixes


def schema_prefixes() -> set[str]:
  with open('validation/schema.json') as f:
    pattern = json.load(f)['$defs']['prefix']['pattern']

  match = re.fullmatch(r'\^\(x_\|\((.*)\)-\)', pattern)
  if match is None:
    raise ValueError(f'unexpected prefix pattern in schema: {pattern}')

  prefixes = set()
  for alternative in match.group(1).split('|'):
    # expand character classes like SUSE-[SRFO]U
    chars = re.search(r'\[(\w+)\]', alternative)
    if chars is None:
      prefixes.add(alternative)
      continue
    for c in chars.group(1):
      prefixes.add(alternative[: chars.start()] + c + alternative[chars.end() :])
  return prefixes


in_table = table_prefixes(table)
in_schema = schema_prefixes()

problems = []
for prefix in sorted(in_table - in_schema):
  problems.append(f'{prefix} is in the docs/schema.md databases table but not in the prefix pattern in validation/schema.json')
for prefix in sorted(in_schema - in_table - PREFIXES_WITHOUT_ROW):
  problems.append(f'{prefix} is in the prefix pattern in validation/schema.json but not in the docs/schema.md databases table')

for problem in problems:
  if 'CI' in os.environ:
    print(f'::error file=docs/schema.md,line={starting_line}::{problem}')
  print(problem)

if problems:
  exit(1)
