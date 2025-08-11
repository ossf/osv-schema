#!/usr/bin/env python3

import os
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


def extract_schema_table() -> str:
  raw_table = ''

  with open('docs/schema.md') as f:
    for line in f.readlines():
      if line == '<table>\n':
        raw_table += line
      if raw_table != '':
        raw_table += line
      if line == '</table>\n':
        break
  return raw_table


table = extract_schema_table()

validator = HTMLValidator()

try:
  validator.feed(table)
except UnexpectedTagError as e:
  if 'CI' in os.environ:
    print(
      f'::error file=docs/schema.md,line=1::unexpected {e} tag in databases table - ensure that the tags are properly paired'
    )
  print(
    f'unexpected {e} tag in docs/schema.md databases table - ensure that the tags are properly paired'
  )
  exit(1)
