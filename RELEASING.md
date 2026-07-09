# Releasing

This document outlines the process for creating a new release of the OSV schema.

## Release Process

The release process is as follows:

1. **Bump the version:**
    - Do a patch version bump for new ecosystems.
    - Do a minor version bump for non-breaking schema field changes.

    The following need to be updated:
    - [`docs/schema.md`](docs/schema.md)
    - [`bindings/go/osvconstants/constants.go`](bindings/go/osvconstants/constants.go)
    - [`scripts/update-ecosystems-lists.py`](scripts/update-ecosystems-lists.py)

2. **Update the changelog:**
    - Add any schema changes to the [`CHANGELOG.md`](CHANGELOG.md) file.

3. **Tag the release:**
    - Create and push a new git tag for the release.

4. **Publish GitHub release:**
    - Create a new release on GitHub with the new version number.

5. **Update GitHub Pages:**
    - Update the `live` branch to the new release.
