#!/usr/bin/env python3
"""
Generates Go constants from enums in the OSV JSON schema by dynamically
discovering enum definitions.

This script works by recursively scanning the JSON schema for properties that
are of type 'string' and have an 'enum' field. For each enum it finds, it
generates a corresponding Go type and a const block containing all the enum's
possible values.

The naming of the generated Go types is determined by heuristics based on the
enum's location (path) within the schema.
"""

import json
import os

# The version is not in the schema, so it's hardcoded here for now.
# This should be kept in sync with the canonical version.
SCHEMA_VERSION = "1.7.3"


def to_pascal_case(s: str) -> str:
    """Converts a snake_case, kebab-case, or space-separated string to PascalCase."""
    s = s.replace('-', '_').replace(' ', '_')
    return ''.join(word.capitalize() for word in s.split('_'))


def convert_enum_value_to_go_name(type_name: str, value: str) -> str:
    """
    Converts an enum value string (e.g., "CVSS_V2") into its Go constant
    name suffix (e.g., "CVSSV2").
    """
    if type_name == 'Ecosystem':
        # Handle special cases for ecosystems that don't fit the standard
        # PascalCase conversion (e.g., 'crates.io').
        if value == 'crates.io':
            return 'CratesIO'
        if value == 'npm':
            return 'NPM'
        # General case for ecosystems.
        name = value[0].upper() + value[1:]
        name = name.replace('-', '').replace(' ', '')
        return name

    if type_name == 'SeverityType':
        if value.startswith('CVSS'):
            return value.replace('_', '')
        # Fallback for other severity types like "Ubuntu".
        return to_pascal_case(value)

    if type_name == 'RangeType' and value == 'SEMVER':
      return 'SemVer'

    # For all other enum types, convert the value to PascalCase.
    # e.g., "REMEDIATION_DEVELOPER" -> "RemediationDeveloper"
    return to_pascal_case(value)


def generate_go_enum(type_name: str, enum_values: list[str]) -> str:
    """
    Generates a Go type definition and a corresponding const block for a
    given enum.
    """
    # Determine the prefix for the constant names by removing 'Type' from the end
    # of the type name. For example, 'CreditType' -> 'Credit'.
    prefix = type_name.replace('Type', '')

    lines = []
    lines.append(f'type {type_name} string')
    lines.append('')
    lines.append('const (')

    constants = []
    # Sort values for deterministic output and handle potential duplicates from
    # different parts of the schema being merged.
    for value in sorted(list(set(enum_values))):
        # Construct the full Go constant name, e.g., "Credit" + "Reporter".
        go_name = prefix + convert_enum_value_to_go_name(type_name, value)
        constants.append((go_name, value))

    # Sort by the generated Go constant name case-insensitively.
    constants.sort(key=lambda x: x[0].casefold())

    if not constants:
        lines.append(')')
        return '\n'.join(lines)

    # Find the longest constant name to align the values for better readability.
    longest_name = max(len(c[0]) for c in constants)

    for name, value in constants:
        lines.append(f'\t{name.ljust(longest_name)} {type_name} = "{value}"')

    lines.append(')')
    return '\n'.join(lines)


def get_type_name_from_path(path: tuple) -> str:
    """
    Derives a descriptive Go type name from a path in the JSON schema.

    This function contains heuristics to generate a good type name. For example,
    if an enum is found at the path ('properties', 'credits', 'items', 'properties', 'type'),
    it will identify 'credits' and 'type' and return 'CreditType'.

    For newly defined enums not covered by the special cases, it falls back to
    using the property name where the enum is defined.
    """
    # Look for specific, well-known paths first to give them clear,
    # explicit names.
    if 'credits' in path and 'type' in path:
        return 'CreditType'
    if 'references' in path and 'type' in path:
        return 'ReferenceType'
    if 'severity' in path and 'type' in path:
        return 'SeverityType'
    if 'ranges' in path and 'type' in path:
        return 'RangeType'
    if 'ecosystemName' in path:
        return 'Ecosystem'

    # Fallback for less specific paths or new enums.
    if path:
        # The property name is usually the last element in the path.
        name_key = str(path[-1])
        # If the enum is defined directly under a 'type' property, the actual
        # name of the field is likely a few levels up the path.
        if name_key == 'type' and len(path) > 2:
            name_key = str(path[-3])
        return to_pascal_case(name_key) + 'Type'

    return 'UnknownType'


def find_enums(schema, path=(), enums=None):
    """
    Recursively traverses the JSON schema to find all string-based enums.
    """
    if enums is None:
        enums = {}

    if isinstance(schema, dict):
        # An enum is identified by the presence of an 'enum' key with a list
        # value, and a 'type' key with the value 'string'.
        if 'enum' in schema and isinstance(
                schema['enum'], list) and schema.get('type') == 'string':

            # Derive a type name (e.g., 'CreditType') from the enum's path.
            type_name = get_type_name_from_path(path)

            # Group all enum values by their derived type name. This handles
            # cases where the same enum is defined in multiple places.
            if type_name not in enums:
                enums[type_name] = []
            enums[type_name].extend(schema['enum'])

        # Continue the recursive search down the schema tree.
        for key, value in schema.items():
            find_enums(value, path + (key, ), enums)

    elif isinstance(schema, list):
        # If the current schema element is a list, iterate through its items.
        for i, item in enumerate(schema):
            find_enums(item, path + (i, ), enums)

    return enums


def main():
    """Main function to generate the Go constants file."""
    # Construct absolute paths to the input schema and the output file.
    script_dir = os.path.dirname(os.path.abspath(__file__))
    schema_path = os.path.join(script_dir, '..', 'validation', 'schema.json')
    output_path = os.path.join(script_dir, '..', 'bindings', 'go', 'osvschema',
                               'constants.go')

    try:
        with open(schema_path, 'r', encoding='utf-8') as f:
            schema = json.load(f)
    except FileNotFoundError:
        print(f"Error: '{schema_path}' not found.")
        return

    # Scan the schema to find all enums.
    enums = find_enums(schema)

    # Prepare the content for the generated Go file.
    output_parts = [
        '// Code generated by scripts/generate-go-constants.py. DO NOT EDIT.',
        'package osvschema', '', f'const SchemaVersion = "{SCHEMA_VERSION}"',
        ''
    ]

    # Generate the Go code for each discovered enum, in alphabetical order.
    for type_name in sorted(enums.keys()):
        enum_values = enums[type_name]
        output_parts.append(generate_go_enum(type_name, enum_values))
        output_parts.append('')

    # Write the generated content to the output file.
    output_content = '\n'.join(output_parts)
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(output_content)

    print(f"Generated Go constants in {output_path}")


if __name__ == '__main__':
    main()
