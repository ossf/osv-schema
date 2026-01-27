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
- 2024-08-21 Released version 1.6.4. Some clarifications for existing fields
  (`aliases`, `affected[].versions[]`), ecosystems (`Android`), and addition of
  new ecosystems (Mageia, Chainguard).
- 2024-09-03 Released version 1.6.5. Added SuSE ecosystems and ELA, UBUNTU ID
  prefixes.
- 2024-09-12 Released version 1.6.6. Add RHBA, RHEA, SUSE-OU prefixes.
- 2024-09-16 Released version 1.6.7. JSON schema and minor text formatting changes.
- 2025-03-05 Released version 1.7.0. Add `upstream` field, `V8-` ID prefix,
  Kubernetes ecosystem, `Ubuntu` severity type.
- 2025-08-05 Released version 1.7.2. Add new ecosystems (openEuler, MinimOS, BellSoft Alpaquita and Hardened Containers, Ubuntu LSN).
- 2025-08-15 Released version 1.7.3. Add Echo ecosystem.
- 2025-10-27 Released version 1.7.4. Add the following prefixes: EFF (Erlang), JLSEC (Julia), ALPINE-, DEBIAN-.
- 2026-01-21 Released version 1.7.5. Add the following ecosystems: opam (OCaml), FreeBSD, Docker Hardened Images (DHI), CleanStart;
  add prefixes: ROOT-OS, ROOT-APP, DRUPAL, OSEC; Also updated Debian ecosystem descriptiuon to support `sid` and `experimental` releases.
