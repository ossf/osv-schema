# EUVD to OSV converter

## Requirements

Go 1.22 or newer is required. The tools use only the Go standard library.

## Usage

```bash
mkdir euvd-data
go run . dump euvd-data
mkdir osv
go run . convert -o osv euvd-data/*.json
```

### Dump options

```text
$ go run . dump --help

USAGE:
	go run . dump [options] out_dir

ARGUMENTS:
	out_dir                         directory for downloaded advisories

OPTIONS:
	--fromDate DATE                 published from date (YYYY-MM-DD)
	--toDate DATE                   published up to date (YYYY-MM-DD)
	--fromScore VALUE               minimum CVSS base score
	--toScore VALUE                 maximum CVSS base score
	--fromEpss VALUE, --epss VALUE  minimum EPSS score (0-100)
	--toEpss VALUE                  maximum EPSS score (0-100)
	--exploited BOOL                exploitation status (true/false)
	--id ID                         EUVD identifier
	--description TEXT              vulnerability description
	--datePublished TEXT            first publication date
	--dateUpdated TEXT              last update date
	--baseScore VALUE               exact CVSS base score
	--baseScoreVersion VERSION      CVSS version (3.1 or 4.0)
	--baseScoreVector VECTOR        full CVSS vector
	--aliases TEXT                  CVE, GHSA, and other identifiers
	--assigner NAME                 assigning organization
	--exploitedSince DATE           date of first known active exploitation
	--product NAME                  affected product
	--vendor NAME                   affected vendor
	--references TEXT               source and fix links
	-h, --help                      show help
```

Date, score-range, EPSS-range, and exploitation filters are sent to the EUVD
search API. The other options filter the returned records locally using
case-insensitive substring matching, except `--baseScore`, which is an exact
match. `--description`, `--assigner`, `--product`, and `--vendor` are also sent
to the API.

Examples:

```bash
go run . dump --vendor nodejs --fromDate 2026-01-01 --toDate 2026-12-31 euvd-data
go run . dump --vendor php euvd-data
```


## Unit Test

```bash
go test ./...
```


