# Change Log

- 2021-03-29 added "withdrawn" field
- 2021-04-07 changed "details" to Markdown, change "references" to a list of
  objects with a new "type" field in addition to the URL.
- 2021-04-23 handful of changes, see Status - 2021-04-23 below for details. Corrected examples.
- 2021-04-26 changed `database-specific` and `ecosystem-specific` to
  `database_specific` and `ecosystem_specific` for easier access from languages
  that access JSON field keys using x.field notation.
- 2021-06-08 Added "purl" to the "package" field and some minor clarifications.
- 2021-06-30 Fixed an incorrect/typoed specification for "affects" from an array
  of objects to an object.
- 2021-08-17 Support multiple packages per entry by moving `packages`,
  `ecosystem_specific` and `database_specific` into `affected`. The `affected`
  field is intentionally named differently to the previous `affects` field to
  make migration easier. Also use "events" containing single versions to
  represent affected version ranges instead.
- 2021-09-08 Promoted schema to 1.0.
- 2022-01-19 Released version 1.2.0. Includes various changes suggested by
  GitHub (`schema_version`, top-level `database_specific`, `credits`,
  `severity`, relaxation of version enumeration requirement).
- 2022-03-24 Released version 1.3.0. Added `last_affected` event type and
  `database_specific` to `affected[].ranges[]`.
  Context: https://github.com/ossf/osv-schema/issues/35.
- 2023-02-21 Released version 1.4.0. Added per package `severity` and
  credit types.
- 2023-04-26 Released version 1.5.0. Added new reference types.
- 2023-08-11 Released version 1.6.0. Several new databases and clarified
  definitions of `aliases` and `related`.
- 2023-11-29 Released version 1.6.1. Some cleanup of the schema layout.
- 2024-01-16 Released version 1.6.2. Added CVSS_V4 and Ubuntu ecosystem.
- 2024-04-05 Released version 1.6.3. Added Maven registry support.
