# OSV Record Linter

A tool for performing data quality checks on OSV records, individually and in aggregate.

## Vision

* OSV record producers are able to run a tool on records they publish, as part of their record publishing pipeline, to discover any data quality issues that might negatively impact the utility of the record by downstream users
* OSV.dev has a repeatable and transparent mechanism for maintaining a quality bar above and beyond what JSON Schema validation enables
* Interested parties can contribute additional checks
* Interested parties may conduct analyses across OSV records in aggregate

Inspired by [github.com/mprpic/cvelint](https://github.com/mprpic/cvelint), and under active development.

### TODO

* Define and implement a machine-readable format for check results to facilitate integration
  * Today, a non-zero return code is the coarse-grained indicator of correctness
* Add a flag to specify checks to be ignored

## Usage

```text
$ go run ./cmd/osv/ record lint --help
NAME:
   osv record lint - check OSV records for correctness

USAGE:
   osv record lint [command options]

OPTIONS:
   --verbose                                  verbose output (default: false)
   --collection value                         check collection to use (use 'list' to see) (default: "ALL")
   --checks value [ --checks value ]          explicitly run a specific check (use 'list' to see)
   --ecosystems value [ --ecosystems value ]  the ecosystems to constrain package checks to (use 'list' to see)
   --help, -h                                 show help
```

```text
$ go run ./cmd/osv record lint test_data
test_data/nointroduced-CVE-2023-41045.json:
         * [R0001]: missing 'introduced' object in event
test_data/nondistinct-CVE-2018-5407.json:
         * [R0002]: overlapping event: "e818b74be2170fbe957a07b0da4401c2b694b3b8"
2024/10/22 00:04:23 found errors
exit status 1
```

```text
$ go run ./cmd/osv/ record lint --checks list
Available checks:

A0001: (affected-data-exists): every record has affected data
R0001: (introduced-event-exists): every range has an introduced event
R0002: (range-is-distinct): range spans multiple versions/commits
P0001: (package-exists): package exists in ecosystem's registry
P0002: (package-versions-exist): package versions exist in ecosystem's registry
P0003: (package-purl-valid): package purl validates
```

```text
$ go run ./cmd/osv/ record lint --collection list
Available check collections:

ALL: all checks currently defined
        A0001: (affected-data-exists): every record has affected data
        R0001: (introduced-event-exists): every range has an introduced event
        R0002: (range-is-distinct): range spans multiple versions/commits
        P0001: (package-exists): package exists in ecosystem's registry
        P0002: (package-versions-exist): package versions exist in ecosystem's registry
        P0003: (package-purl-valid): package purl validates
offline: checks that do not have remote data dependencies
        A0001: (affected-data-exists): every record has affected data
        R0001: (introduced-event-exists): every range has an introduced event
        R0002: (range-is-distinct): range spans multiple versions/commits
        P0003: (package-purl-valid): package purl validates
```

## Contributing

Contributions are very welcome!

Checks should be as atomic as possible.

### Adding checks

* Define in `internal/checks`, based on the nature of the check
  * `packages.go`
  * `ranges.go`
  * `record.go`
  * Define a new variable of type `&CheckDef`, in the name format `Check` + *thing* + *assertion* (where *thing* is field of an OSV record and *assertion* is what is being checked)
  * Implement a function that takes a `*gjson.Result` and a `*Config` and returns `[]CheckError`
    * Include tests and sample records that both pass and fail this check
* Add the new `&CheckDef` variable to `Collections` in `internal/checks/checks.go`
* See [#295](https://github.com/ossf/osv-schema/pull/295) for a worked example

### Additional references

* [Open Source Vulnerability schema](https://ossf.github.io/osv-schema/)
* [Properties of a High Quality OSV Record](https://google.github.io/osv.dev/data_quality.html)
* [GJSON](https://github.com/tidwall/gjson)
  * [Go package](https://pkg.go.dev/github.com/tidwall/gjson)
  * [Syntax](https://github.com/tidwall/gjson/blob/master/SYNTAX.md)
  * [Playground](https://gjson.dev/)
