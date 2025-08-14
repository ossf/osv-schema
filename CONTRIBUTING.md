# How to Contribute

We'd love to accept your patches and contributions to this project. There are
just a few small guidelines you need to follow.

## Code of Conduct

This is a project of the [Open Source Security Foundation](https://github.com/ossf/) and follows its [Code of Conduct](CODE_OF_CONDUCT.md).

## Accepted Contributions

This repository is primarily for the OSV Schema definition([human-readable](docs/schema.md) and [JSON Schema](validation/schema.json)), and related tooling.

See the [guiding principles](GUIDING_PRINCIPLES.md) for background thinking behind the schema's design, and what is more and less likely to be acceptable in the way of changes.

For more substantial changes, we encourage you to open an issue for discussion and to also engage with the [OpenSSF Vulnerability Working Group](https://github.com/ossf/wg-vulnerability-disclosures/) about the proposed change.

## Code Reviews

All submissions, including submissions by project members, require review. We
use GitHub pull requests for this purpose. Consult
[GitHub Help](https://help.github.com/articles/about-pull-requests/) for more
information on using pull requests.

## Adding a new ecosystem

To add a new ecosystem, follow these steps:

1.  **`ecosystems.json`**: Add an entry for the new ecosystem and it's description.
    * If your ecosystem has multiple separate release, please include how releases are specified.

2.  **Database-specific prefix**: Generally a new ecosystem will introduce a new database-specific ID prefix (e.g., `GHSA` for GitHub Security Advisories), please add it to:
    *   The "Database-specific prefixes" table in `docs/schema.md`.
    *   The `prefix` pattern within `validation/schema.json`.

3.  **`README.md`**: Add the new ecosystem to the list of data exporters in the README.

4.  **Run update script**: Finally, run `python3 ./scripts/update-ecosystems-lists.py`. This script will automatically update the following files based on your changes to `ecosystems.json`:
    *   `bindings/go/osvschema/constants.go`
    *   The main ecosystem table in `docs/schema.md`
    *   The ecosystem enum in `validation/schema.json`
    *   Make a copy of the `validation/schema.json` for the linter in `tools/osv-linter/internal/checks/schema_generated.json`
