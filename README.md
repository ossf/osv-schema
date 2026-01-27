# Open Source Vulnerability (OSV) Schema

[Rendered Specification](https://ossf.github.io/osv-schema/)

## Overview

The OSV schema provides a human and machine-readable format to describe vulnerabilities that map precisely to open source package versions or commit hashes. It is used by multiple distributions and advisory databases and is the canonical format aggregated by <https://osv.dev>.

## Quick links

- Specification (rendered): <https://ossf.github.io/osv-schema/>
- JSON Schema: [schema.json](validation/schema.json)
- Protocol buffer definition: [proto/vulnerability.proto](proto/vulnerability.proto)
- Tools and converters: [tools/](tools)

## Getting started

Installers and consumers typically use one of the available converters or the rendered spec above. Example data sources that export or convert to OSV include many distro and advisory projects (AlmaLinux, Debian, PyPI advisories, RustSec, etc.). See the `tools/` directory for converters maintained alongside this repo.

## Using the schema

Common tasks:

- Validate a file against the JSON schema: `scripts/validate-schema-table.py` and `schema.json`.
- Convert vendor-specific advisories: see `tools/` subfolders (e.g., `tools/debian`, `tools/ghsa`).
- Generate Protobuf types: `proto/vulnerability.proto` contains the canonical proto.

## Adoption

There are many home databases publishing OSV-format advisories or maintain converters:

- [AlmaLinux](https://github.com/AlmaLinux/osv-database)
- [BellSoft Security Advisory](https://github.com/bell-sw/osv-database)
- [Bitnami Vulnerability Database](https://github.com/bitnami/vulndb)
- [Chainguard](https://packages.cgr.dev/chainguard/osv/all.json)
- [CleanStart](https://github.com/cleanstart-dev/cleanstart-security-advisories)
- [Curl](https://curl.se/docs/vuln.json)
- [Echo](https://advisory.echohq.com/osv/all.json)
- [GitHub Security Advisories](https://github.com/github/advisory-database)
- [Global Security Database](https://github.com/cloudsecurityalliance/gsd-database)
- [Go Vulnerability Database](https://github.com/golang/vulndb)
- [Haskell Security Advisories](https://github.com/haskell/security-advisories)
- [Julia Security Advisories](https://github.com/JuliaLang/SecurityAdvisories.jl)
- [LoopBack Advisory Database](https://github.com/loopbackio/security/tree/main/advisories)
- [Malicious Packages Repository](https://github.com/ossf/malicious-packages)
- [Mageia Advisories](https://advisories.mageia.org/)
- [MinimOS](https://packages.mini.dev/advisories/osv/all.json)
- [OCaml](https://github.com/ocaml/security-advisories)
- [openEuler](https://repo.openeuler.org/security/data)
- [OSS-Fuzz](https://github.com/google/oss-fuzz-vulns)
- [OSV.dev maintained converters](https://github.com/google/osv.dev#current-data-sources) (Debian, Alpine, NVD)
- [PyPI Advisory Database](https://github.com/pypa/advisory-database)
- [Python Software Foundation Database](https://github.com/psf/advisory-database)
- [RConsortium Advisory Database](https://github.com/RConsortium/r-advisory-database)
- [Red Hat](https://security.access.redhat.com/data)
- [Rocky Linux](https://distro-tools.rocky.page/apollo/openapi/#osv)
- [Root](https://api.root.io/external/osv/all.json)
- [Rust Advisory Database](https://github.com/RustSec/advisory-db)
- [SUSE](https://www.suse.com/support/security/)
- [Ubuntu](https://github.com/canonical/ubuntu-security-notices/)
- [VMWare Photon OS](https://github.com/vmware/photon/wiki/Security-Advisories) (unofficial)

Together, these include vulnerabilities from:

- AlmaLinux
- Alpine
- Alpaquita Linux
- Android
- Azure Linux
- BellSoft Hardened Containers
- Bitnami
- Chainguard
- CleanStart
- crates.io
- Debian GNU/Linux
- Docker
- Echo
- Erlang Ecosystem Foundation
- FreeBSD
- GitHub Actions
- Go
- Haskell
- Hex
- Julia
- Linux kernel
- Mageia
- Maven
- MinimOS
- npm
- NuGet
- OCaml
- openEuler
- openSUSE
- OSS-Fuzz
- Packagist
- Photon OS
- Pub
- PyPI
- Python
- R (CRAN and Bioconductor)
- Red Hat
- SUSE
- Rocky Linux
- RubyGems
- Ubuntu

See the repository history and the `tools/` subdirectories for more examples and testdata.

## Development

Prerequisites:

- Python 3 for scripts in `tools/` and `scripts/`.
- (Optional) Go for components under `bindings/go`.

Common development tasks:

- Run schema validation: `python3 scripts/validate-schema-table.py` (see script for usage).
- Run converter tests: check subdirectories in `tools/*/` for test instructions.

## Contributing

We welcome contributions. Please follow the repository's contributor guidelines and code of conduct:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

If you find a bug or want to request a feature, open an issue in this repository.

## Community and support

Join the OpenSSF Slack channel `#osv_schema` (Slack invite: <https://slack.openssf.org/>) to discuss the schema and tooling.

## Maintainers

This repository is maintained by the OpenSSF Vulnerability Disclosures Working Group. See the repository `CODEOWNERS` for current maintainers.

## License

This project is licensed under the terms in the repository `LICENSE` file.

## Security

To report a security issue, follow the instructions in `SECURITY.md`.

## Acknowledgements

OSV Schema is used and supported by many projects and ecosystems. See the rendered specification and the `tools/` directory for a (non-exhaustive) list of converters and consumers.
