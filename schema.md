# Open Source Vulnerability format

**Version 0.8 (August 5, 2021)**

Original authors:
- Oliver Chang (ochang@google.com)
- Russ Cox (rsc@google.com)

## Purpose

There are many problems to solve industry-wide concerning vulnerability
detection, tracking, and response. One low-level problem is that there are many
databases and no standard interchange format. A client that wants to aggregate
information from multiple databases must handle each database completely
separately. Databases that want to exchange information with each other must
also each have their own parser for each format. Systematic tracking of
dependencies and collaboration between vulnerability database efforts is
hampered by not having a common interchange format. See our
[blog post](https://security.googleblog.com/2021/06/announcing-unified-vulnerability-schema.html) for more details.

This document defines a draft of a standard interchange format.
We hope to define a format that all vulnerability databases can export, to make
it easier for users, security researchers, and any other efforts to consume all
available databases. Use of this format would also make it easier for the
databases themselves to share or cross-check information.

This shared interchange format is not expected to be the internal format for any
particular database. We hope only that every vulnerability database will make
its entries available in this format to enable interoperability.

The idea for this format originally arose from discussions between the [Go
vulnerability database](https://golang.org/design/draft-vulndb) team and the
[OSV](https://osv.dev) team. We are grateful for early feedback from members of
various security response teams.

This format is a work in progress. Feedback from maintainers of other
vulnerability databases is most welcome. Please feel free to create an issue in
this repo.

The questions we’d like to answer are:
 - Is this an effort you’d like to participate in?
 - Does this format contain what your database would want to know from other databases?
 - Would you be willing to make your database available in this format?

## Format Overview

The format is a JSON-based encoding format, using the following informal schema.
The exact details of each field are elaborated in the next section. All strings
contain UTF-8 text.

```json
{
	"id": string,
	"modified": string,
	"published": string,
	"withdrawn": string,
	"aliases": [ string ],
	"related": [ string ],
	"summary": string,
	"details": string,
	"affected": [ {
		"package": {
			"ecosystem": string,
			"name": string,
			"purl": string,
		},
		"ranges": [ {
			"type": string,
			"repo": string,
			"introduced": string,
			"fixed": string
		} ],
		"versions": [ string ],
		"platforms": [ string ],
		"routines": [ string ],
		"ecosystem_specific": { see description },
		"database_specific": { see description },
	} ],
	"references": [ {
		"type": string,
		"url": string
	} ],
}
```

Again, this document is only about the JSON encoding the database serves to
consumers, which could be applications or other databases. A database might
store its entries in an entirely different format, or it might store them using
this schema but in a more human-editable encoding, such as TOML or YAML. For
serving, only the JSON encoding format is allowed,
not a transliteration into any other encoding.

Overall, the approach of this schema is to define only the fields that
absolutely must be shared between databases, leaving customizations to the
"ecosystem_specific" and "database_specific" blocks (see below)

## Field Details

### id, modified fields

The `id` field is a unique identifier for the vulnerability entry. It is a
string of the format `<DB>-<ENTRYID>`, where `DB` names the database and
`ENTRYID` is in the format used by the database. For example: "OSV-2020-111",
"CVE-2021-3114", or "GHSA-vp9c-fpxx-744v".

The defined database prefixes and their "home" databases are:

- `Go`: the Go vulnerability database.
  Serving <ID> in the shared format at `https://vuln.golang.org/<ID>.json`
- `OSV`: the osv.dev vulnerability database.
  Serving <ID> in the shared format at `https://api.osv.dev/v1/vulns/<ID>`
- `PYSEC`: The PyPI vulnerability database.
  Serving <ID> in the shared format at  `https://api.osv.dev/v1/vulns/<ID>`
- `RUSTSEC`: The Rust crates vulnerability database.
  Serving <ID> in the shared format at  `https://github.com/RustSec/advisory-db/blob/osv-experimental-v0.7/crates/<ID>.json`
- `UVI`: The UVI database.
  Serving <ID> in the shared format at `https://github.com/cloudsecurityalliance/uvi-database/`.
- Your database here. Send us a PR.

In addition to those prefixes, other databases may serve information about
non-database-specific prefixes. For example a language ecosystem might decide to
use CVE identifiers to index its database rather than a custom prefix. The known
databases operating without custom identifier prefixes are:

- (Currently none.)
- Your database here. Send us a PR.

The `modified` field gives the time the entry was last modified, as an
RFC3339-formatted timestamptime stamp in UTC (ending in "Z"). Given two
different entries claiming to describe the same `id` field, the one with the
later modification time is considered authoritative.

The `id` and `modified` fields are required. All other fields are optional,
although of course an entry with no other metadata is not particularly useful.
(It could potentially stand for a reserved ID with no other public information.)

### published field

The `published` field gives the time the entry should be considered to have been
published, as an RFC3339-formatted time stamp in UTC (ending in "Z").

### withdrawn field

The `withdrawn` field gives the time the entry should be considered to have been
withdrawn, as an RFC3339-formatted timestamp in UTC (ending in "Z"). If the
field is missing, then the entry has not been withdrawn. Any rationale for why
the vulnerability has been withdrawn should go into the summary text.

### aliases field

The `aliases` field gives a list of IDs of the same vulnerability in other
databases, in the form of the `id` field. This allows one database to claim that
its own entry describes the same vulnerability as one or more entries in other
databases. Or if one database entry has been deduplicated into another in the
same database, the duplicate entry could be written using only the `id`,
`modified`, and `aliases` field, to point to the canonical one.

### related field

The `related` field gives a list of IDs of closely related vulnerabilities, such
as the same problem in alternate ecosystems. 

### summary, details fields

The `summary` field gives a one-line, English textual summary of the
vulnerability. It is recommended that this field be kept short, on the order of
no more than 120 characters.

The `details` field gives additional English textual details about the
vulnerability. The field is plain text. Newline characters must be considered
line breaks when displaying the text, but the display need not use a fixed-width
font, and the text should not assume one.

The `summary` field is plain text.

The `details` field is CommonMark markdown (a subset of GitHub-Flavored
Markdown). Display code may at its discretion sanitize the input further, such
as stripping raw HTML and links that do not start with http:// or https://.
Databases are encouraged not to include those in the first place. (The goal is
to balance flexibility of presentation with not exposing vulnerability database
display sites to unnecessary vulnerabilities.)

### affected fields

The `affected` field is a JSON array containing objects that describes the
affected packages versions, meaning those that contain the vulnerability.

Within each object in the `affected` array, the `package` field identifies the
package containing the vulnerability.

The `versions` field can enumerate a specific set of affected versions, and the
`ranges` field can list ranges of affected versions, under a given defined
ordering. A version is considered affected if it lies within any one of the
ranges or is listed in the versions list.

The `versions` list should - with one exception - always be present, to allow
software to answer the question "is this specific version affected?" without
having to contain code specific to every different ecosystem. The one exception
is if the affected versions are valid SemVer 2.0 versions which can be
accurately summarized by one or more non-overlapping SemVer ranges. In that
case, the SemVer ranges can be listed instead, in entries in the `ranges` field
with type `SEMVER` (see below). In this case, the SemVer ranges act as a kind of
compact form of a larger `versions` list. Ecosystems that do not use SemVer
identifiers or that order versions differently from SemVer must include the
enumerated `versions` list, although they can also add ranges of type
`ECOSYSTEM` for additional context.

In short, each object in the `affected` array must contain either a non-empty
`versions` list or at least one range in the `ranges` list of type `SEMVER`.

#### affected[].package field

The `affected` object's `package` field is a JSON object identifying the
affected code library or command provided by the package. The object itself has
two required fields, `ecosystem` and `name`, and an optional `purl` field.

The `ecosystem` identifies the overall library ecosystem. It must be one of the
strings in the table below. The `name` field is a string identifying the library
within its ecosystem. The two fields must both be present, because the
`ecosystem` serves to define the interpretation of the `name`.

The `purl` field is a string following the
 [Package URL specification](https://github.com/package-url/purl-spec) that
identifies the package. This field is optional but recommended.

Different ecosystems can define the same names; they identify different
packages. For example, these denote different libraries with different sets of
versions and different potential vulnerabilities:

`{"ecosystem": "npm", "name": "zlib"}`

`{"ecosystem": "PyPI", "name": "zlib"}`

The defined ecosystems are:

- `Go`: the Go ecosystem; the `name` field is a Go module path.
- `npm`: the NPM ecosystem; the `name` field is an NPM package name.
- `OSS-Fuzz`: for reports from the OSS-Fuzz project that have no more
  appropriate ecosystem; the `name` field is the name assigned by the OSS-Fuzz
  project, as recorded in the submitted fuzzing configuration.
- `PyPI`: the Python PyPI ecosystem; the `name` field is a
  [normalized](https://www.python.org/dev/peps/pep-0503/#normalized-names) PyPI
  package name.
- `RubyGems`: The RubyGems ecosystem; the `name` field is a gem name.
- `crates.io`: The crates.io ecosystem for Rust; the `name` field is a crate name.
- `Packagist`: The PHP package manager ecosystem; the `name` is a package name.
- `Maven`: The Maven Java package ecosystem. The `name` field is a Maven package
  name.
- `NuGet`: The NuGet package ecosystem. The `name` field is a NuGet package
  name.
- `Linux`: The Linux kernel. The only supported `name` is `Kernel`.
- Your ecosystem here. Send us a PR.

It is permitted for a database name (the DB prefix in the `id` field) and an
ecosystem name to be the same, provided they have the same owner who can make
decisions about the meaning of the `ecosystem_specific` field (see below).

#### affected[].versions

The `affected` object's `versions` field is a JSON array of strings. Each string
is a single affected version in whatever version syntax is used by the given
package ecosystem.

#### affected[].ranges

The `affected` object's `ranges` field is a JSON array of objects, each
describing a single range.  The range object defines the fields `type`,
`introduced`, `fixed`, and additional type-specific fields as needed.

In the range object, the `type` field is required. It specifies the type of
version range being recorded and defines the interpretation of `introduced`,
`fixed`, and any type-specific fields.

The `introduced` and `fixed` fields specify the range of versions containing the
vulnerability.  The vulnerability is considered present in version v if:

```
(introduced is unset OR introduced < v OR introduced == v) AND
(fixed is unset OR v < fixed).
```

Here `u == v` is exact version equality and the meaning of the relation `u < v`
depends on the type.

The defined types and their additional fields are:

- `SEMVER`: The versions `introduced` and `fixed` are semantic versions as defined
by [SemVer 2.0.0](https://semver.org), with no leading "v" prefix. The relation
`u < v` denotes the precedence order defined in [section 11 of SemVer 2.0](https://semver.org/#spec-item-11).
Ranges listed with type `SEMVER` should not overlap: since SEMVER is a strict
linear ordering, it is always possible to simplify to non-overlapping ranges.

  Specifying one or more `SEMVER` ranges removes the requirement to specify an
explicit enumerated `versions` list (see the discussion above).

- `ECOSYSTEM`: The versions `introduced` and `fixed` are arbitrary, uninterpreted
strings specific to the package ecosystem, which does not conform to SemVer
2.0’s version ordering.

  Specifying one or more `ECOSYSTEM` ranges does NOT remove the requirement to
specify an explicitly enumerated `versions` list, because `ECOSYSTEM` range
inclusion queries cannot be answered without reference to the package
ecosystem’s own logic and therefore cannot be used by ecosystem-independent
processors.

- `GIT`: The versions `introduced` and `fixed` are full-length Git commit hashes.
The additional field `repo` is the URL of the Git repository (as used with `git
clone`). The repository’s commit graph is needed to evaluate whether a given
version is in the range. The relation `u < v` is true when commit `u` is a (perhaps
distant) parent of commit `v`. Ranges listed with type `GIT` may need to overlap,
if a vulnerability with a single root cause was fixed independently on multiple
branches.

  Specifying one or more `GIT` ranges does NOT remove the requirement to specify
an explicitly enumerated `versions` list, because `GIT` range inclusion queries
cannot be answered without access to a copy of the underlying Git repository.

Again, it is important to note that to allow portable (non-ecosystem-specific)
processors to answer "is this version affected?", either `SEMVER` ranges or an
explicit `versions` list must be given. The `ECOSYSTEM` and `GIT` ranges
are only for adding additional context.

#### affected[].platforms field

The `affected` object's `platforms` field is a JSON array of strings. Each
string describes a platform that is affected. The values of these strings are
ecosystem-dependent.

#### affected[].routines field

The `affected` object's `routines` field is a JSON array of strings. Each string
describes a source code function, method or subroutine that is affected.  The
values of these strings are ecosystem-dependent.

#### affected[].ecosystem_specific field

The `affected` object's `ecosystem_specific` field is a JSON object holding
additional information about the vulnerability as defined by the ecosystem for
which the record applies. The meaning of the values within the object is
entirely defined by the ecosystem and beyond the scope of this document.

For example, the Go ecosystem includes here information about the affected
functions and which modules the packages were found in, along with severity in
the Go project-specific severity scale.

Note that this is a single field with key "ecosystem_specific", which itself
contains a JSON object with unspecified fields.

#### affected[].database_specific field

The `affected` object's `database_specific` field is a JSON object holding
additional information about the vulnerability as defined by the database from
which the record was obtained. The meaning of the values within the object is
entirely defined by the database and beyond the scope of this document.

In general, the canonical database for a particular ecosystem should record its
information in `ecosystem_specific`, allowing other aggregator databases to put
their own summaries in `database_specific`. 

For example, databases that add additional information such as computed CVSS
scores for ecosystems that do not provide them could add that information here.

Note that this is a single field with key "database_specific", which itself
contains a JSON object with unspecified fields.

### references field

The `references` field contains a list of JSON objects describing references.
Each object has a string field `type` specifying the type of reference, and a
string field `url`. The `url` is the fully-qualified URL (including the scheme,
typically "https://") linking to additional information, advisories, issue
tracker entries, and so on about the vulnerability itself. The `type` specifies
what kind of reference the URL is.

The known reference `type` values are:

- `ADVISORY`: A published security advisory for the vulnerability.
- `ARTICLE`: An article or blog post describing the vulnerability.
- `REPORT`: A report, typically on a bug or issue tracker, of the vulnerability.
- `FIX`: A source code browser link to the fix (e.g., a GitHub commit) Note that
  the `fix` type is meant for viewing by people using web browsers.  Programs
  interested in analyzing the exact commit range would do better to use the
  `GIT`-typed `affected[].ranges` entries (described above).
- `PACKAGE`: A web page for the affected package itself.
- `WEB`: A web page of some unspecified kind. 

## Examples

### Go vulnerability

The Go vulnerability database and ecosystem define that the `ecosystem_specific`
field is a JSON object with additional fields including `module`, the Go module
in which the package appears.

Here is a complete entry for a recent Go vulnerability:

```json
{
    "id": "Go-2021-99998",
    "published": "2021-01-21T19:15:00Z",
    "modified": "2021-03-10T23:20:53Z",
    "aliases": ["CVE-2021-3114"],
    "summary": "incorrect P-224 curve operations",
    "details": "The P224() Curve implementation can in rare circumstances generate incorrect outputs, including returning invalid points from ScalarMult.\n\nThe crypto/x509 and golang.org/x/crypto/ocsp (but not crypto/tls) packages support P-224 ECDSA keys, but they are not supported by publicly trusted certificate authorities. No other standard library or golang.org/x/crypto package supports or uses the P-224 curve.\n\nThe incorrect output was found by the elliptic-curve-differential-fuzzer project running on OSS-Fuzz and reported by Philippe Antoine (Catena cyber).",
    "references": [
        {"type": "REPORT", "url": "https://golang.org/issue/43786"},
        {"type": "WEB", "url": "https://github.com/catenacyber/elliptic-curve-differential-fuzzer"},
    ],
    "affected": [ {
        "package": {
            "ecosystem": "Go",
            "name": "crypto/elliptic"
        },
        "ranges": [
            {"type": "SEMVER", "introduced": "1.0.0", "fixed": "1.14.14"},
            {"type": "SEMVER", "introduced": "1.15.0", "fixed": "1.15.17"}
        ],
        "routines": ["P224"],
        "ecosystem_specific": {
            "module": "std",
            "severity": "HIGH"
        }
    } ]
}
```

### Go tool vulnerability

The shared format can also be used to describe vulnerabilities in commands and
applications.  Here is an entry for a recent Go tool vulnerability:

```json
{
    "id": "Go-2021-99999",
    "published": "2021-01-21T19:15:00Z",
    "modified": "2021-03-10T23:20:53Z",
    "aliases": ["CVE-2021-3115"],
    "summary": "packages using cgo can cause arbitrary code execution at build time",
    "details": "The go command may execute arbitrary code at build time when cgo is in use on Windows. This may occur when running "go get", or any other command that builds code. Only users who build untrusted code (and don’t execute it) are affected.\n\nIn addition to Windows users, this can also affect Unix users who have "." listed explicitly in their PATH and are running "go get" or build commands outside of a module or with module mode disabled.\n\nThanks to RyotaK (https://twitter.com/ryotkak) for reporting this issue.",
    "references": [
        {"type": "REPORT", "url": "https://golang.org/issue/43783"}
    ],
    "affected": [ {
        "package": {
            "ecosystem": "Go",
            "name": "cmd/go"
        },
        "ranges": [
            {"type": "SEMVER", "introduced": "1.0.0", "fixed": "1.14.14"},
            {"type": "SEMVER", "introduced": "1.15.0", "fixed": "1.15.17"}
        ],
        "ecosystem_specific": {
            "severity": "HIGH"
        }
    } ]
}
```

### NPM vulnerability in GitHub database

Neither GitHub nor NPM uses this format currently, but here is how a recent NPM vulnerability would look as part of the GitHub database assuming the NPM ecosystem is allocated.

```json
{
    "id": "GHSA-r9p9-mrjm-926w",
    "published": "2021-03-07T11:27:00Z",
    "modified": "2021-03-10T23:40:39Z",
    "aliases": ["NPM-1648", "CVE-2020-28498", "SNYK-JS-ELLIPTIC-1064899"],
    "related": ["NPM-1649", "SNYK-JAVA-ORGWEBJARSNPM-1069836"],
    "summary": "Use of a Broken or Risky Cryptographic Algorithm",
    "details": "elliptic is a Fast elliptic-curve cryptography in a plain javascript implementation.\n\nAffected versions of this package are vulnerable to Cryptographic Issues via the secp256k1 implementation in elliptic/ec/key.js. There is no check to confirm that the public key point passed into the derive function actually exists on the secp256k1 curve. This results in the potential for the private key used in this implementation to be revealed after a number of ECDH operations are performed.\n\nRemediation: Upgrade elliptic to version 6.5.4 or higher.\n",
    "references": [
        {"type": "ADVISORY", "url": "https://www.npmjs.com/advisories/1648"},
        {"type": "ADVISORY", "url": "https://nvd.nist.gov/vuln/detail/CVE-2020-28498"},
        {"type": "FIX", "url": "https://github.com/indutny/elliptic/commit/441b7428"},
        {"type": "ARTICLE", "url": "https://github.com/christianlundkvist/blog/blob/master/2020_05_26_secp256k1_twist_attacks/secp256k1_twist_attacks.md"},
        {"type": "ADVISORY", "url": "https://snyk.io/vuln/SNYK-JS-ELLIPTIC-1064899"},
        {"type": "PACKAGE", "url": "https://www.npmjs.com/package/elliptic"}
    ],
    "affected": [ {
        "package": {
            "ecosystem": "npm",
            "name": "elliptic"
        },
        "ranges": [
            {"type": "SEMVER", "fixed": "6.5.4"},
            {"type": "SEMVER", "introduced": "1.15.0", "fixed": "1.15.17"}
        ],
        "database_specific": {
            "CWE": "CWE-327",
            "CVSS": {
                "Score": "6.8",
                "Severity": "Medium",
                "Code": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:N/A:N"
            }
        }
    } ]
}
```

### OSV vulnerability

OSV uses this format already for its vulnerabilities. Here is the encoding of one entry:

```json
{
    "id": "OSV-2020-584",
    "published": "TODO 2021-01-21T19:15:00Z",
    "modified": "TODO 2021-03-10T23:20:53Z",
    "summary": "Heap-buffer-overflow in collator_compare_fuzzer.cpp",
    "details": "OSS-Fuzz report: https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=15499\nCrash type: Heap-buffer-overflow WRITE 3\nCrash state:\ncollator_compare_fuzzer.cpp\n",
    "references": [
        {"type": "REPORT", "url": "https://bugs.chromium.org/p/oss-fuzz/issues/detail?id=15499"},
    ],
    "affected": [ {
        "package": {
            "ecosystem": "OSS-Fuzz",
            "name": "icu"
        },
        "ranges": [
            {
                "type": "GIT",
                "introduced": "6e5755a2a833bc64852eae12967d0a54d7adf629",
                "fixed": "c43455749b914feef56b178b256f29b3016146eb",
                "repo": "https://github.com/unicode-org/icu.git"
            }
        ]
    } ]
}
```

### Rust vulnerability

The [Rust advisory DB](https://github.com/RustSec/advisory-db) exports this
format. Here’s an example entry:

```json
{
    "id": "RUSTSEC-2019-0033",
    "published": "2019-11-16T00:00:00Z",
    "modified": "2021-01-04T19:02:00Z",
    "aliases": ["CVE-2020-25574", "CVE-2019-25008"],
    "summary": "Integer Overflow in HeaderMap::reserve() can cause Denial of Service",
    "details": "HeaderMap::reserve() used usize::next_power_of_two() to calculate\nthe increased capacity. However, next_power_of_two() silently overflows\nto 0 if given a sufficently large number in release mode.\n\nIf the map was not empty when the overflow happens, the library will invoke self.grow(0)\nand start infinite probing. This allows an attacker who controls\nthe argument to reserve() to cause a potential denial of service (DoS).\n\nThe flaw was corrected in 0.1.20 release of http crate.\n",
    "references": [
      {"type": "REPORT", "url": "https://github.com/hyperium/http/issues/352"},
      {"type": "ADVISORY", "url": "https://rustsec.org/advisories/RUSTSEC-2019-0033.html"}
    ],
    "affected": [ {
        "package": {
            "ecosystem": "crates.io",
            "name": "http"
        },
        "ranges": [
            {"type": "SEMVER", "fixed": "0.1.20"},
        ],
        "routines": ["http::header::HeaderMap::reserve"],
        "ecosystem_specific": {
            "keywords": ["http", "integer-overflow", "DoS"],
            "categories": ["denial-of-service"],
            "severity": "HIGH"
        }
    } ]
}
```

### Python vulnerability

Python currently has a [community vulnerability
database](https://github.com/pypa/advisory-db) using this format. Here is a
potential encoding of a vulnerability entry.

```json
{
    "id": "PYSEC-2021-XXXX",
    "published": "2021-04-01T20:15:00Z",
    "modified": "2021-04-07T15:14:00Z",
    "aliases": ["CVE-2021-29421"],
    "summary": "XXE in pikepdf",
    "details": "models/metadata.py in the pikepdf package 2.8.0 through 2.9.2 for Python allows XXE when parsing XMP metadata entries.",
    "references": [
        {"type": "FIX", "url": "https://github.com/pikepdf/pikepdf/commit/3f38f73218e5e782fe411ccbb3b44a793c0b343a"}
    ],
    "affected": [ {
        "package": {
            "ecosystem": "PyPI",
            "name": "pikepdf"
        },
        "ranges": [
            {
                "type": "GIT",
                "repo": "https://github.com/pikepdf/pikepdf",
                "fixed": "3f38f73218e5e782fe411ccbb3b44a793c0b343a"
            },
            {
                "type": "ECOSYSTEM",
                "introduced": "2.8.0",
                "fixed": "2.10.0"
            }
        ],
        "versions": [
                "2.8.0", "2.8.0.post1", "2.8.0.post2", "2.9.0", "2.9.1", "2.9.2"
        ],
        "ecosystem_specific": {
            "severity": "HIGH"
        }
    } ]
}
```

### Ruby vulnerability
Ruby does not use this format currently, but here is a potential translation of one Ruby advisory:

```json
{
    "id": "CVE-2019-3881",
    "published": "2018-04-23T00:00:00Z",
    "modified": "2021-05-10T00:00:00Z",
    "summary": "Insecure path handling in Bundler",
    "details": "Bundler prior to 2.1.0 uses a predictable path in /tmp/, created with insecure permissions as a storage location for gems, if locations under the user's home directory are not available. If Bundler is used in a scenario where the user does not have a writable home directory, an attacker could place malicious code in this directory that would be later loaded and executed.",
    "affected": [ {
        "package": {
            "ecosystem": "RubyGems",
            "name": "bundler"
        },
        "ranges": [
            {"type": "ECOSYSTEM", "introduced": "1.14.0", "fixed": "2.1.0"}
        ],
        "versions": [
            "1.14.0", "1.14.1", "1.14.2", "1.14.3", "1.14.4", "1.14.5", 
            "1.14.6", "1.15.0.pre.1", "1.15.0.pre.2", "1.15.0.pre.3",
            "1.15.0.pre.4", "1.15.0", "1.15.1", "1.15.2", "1.15.3", "1.15.4", 
            "1.16.0.pre.1", "1.16.0.pre.2", "1.16.0.pre.3", "1.16.0", 
            "1.16.1", "1.16.2", "1.16.3", "1.16.4", "1.16.5", "1.16.6", 
            "1.17.0.pre.1", "1.17.0.pre.2", "1.17.0", "1.17.1", "1.17.2",
            "1.17.3", "2.0.0.pre.1", "2.0.0.pre.2", "2.0.0.pre.3", "2.0.0", 
            "2.0.1", "2.0.2", "2.1.0.pre.1", "2.1.0.pre.2", "2.1.0.pre.3"
        ]
    } ],
    "references": [
        {"type": "ADVISORY", "url": "https://github.com/advisories/GHSA-g98m-96g9-wfjq"}
    ]
}
```

## Change Log

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
- 2021-08-05 Support multiple packages per entry by moving `packages`,
  `ecosystem_specific` and `database_specific` into `affected`. Added `routines`
  and `platforms` to `affected` as well. The `affected` field is intentionally
  named differently to the previous `affects` field to make migration easier.

## Status - 2021-04-07

The unresolved open issues boil down to what the use case is for this data.

The use case we had in mind was enabling computer processing of
vulnerability databases, so that for example:

A web site can display information about a vulnerability fetched from an unaffiliated database.
A security researcher can fetch precise info about which versions are vulnerable for offline analysis.
A vulnerability-checking tool can check a build manifest against a collection of these entries to see which are included in the build and then report a summary.

The vision we had for this was that the same underlying vulnerability might be
described by multiple databases. We wanted a way for databases to be able to
cross-link with each other and understand what the others were publishing.  

See also the "Goal: Standard Schema for Vulnerability Databases" section in
https://security.googleblog.com/2021/02/know-prevent-fix-framework-for-shifting.html,
which I’ll quote here:

> Goal: Standard Schema for Vulnerability Databases

> Infrastructure and industry standards are needed to track and maintain open
> source vulnerabilities, understand their consequences, and manage their
> mitigations. A standard vulnerability schema would allow common tools to work
> across multiple vulnerability databases and simplify the task of tracking,
> especially when vulnerabilities touch multiple languages or subsystems.

It was a non-goal to unify the entries in different existing databases into a
single entry for a particular vulnerability.

The open issues that remain seem to be pushing toward a new use case, which is
to be able to unify the entries in different existing databases into a single
entry (for a particular vulnerability). That was a non-goal: the assumption is
that there will always be multiple databases, because at the least each
ecosystem will have its own database with its own custom metadata that doesn't
really make sense to other databases. 

The open issue for "delete severity" illustrates this. If you are only
collecting info from an ecosystem's database, it probably does help to be able
to find out what that ecosystem calls the severity of the vulnerability. But
obviously if you are trying to provide a one-true-entry, then it's not going to
make sense to have a global idea of severity.

The open issue for being able to give the affected versions across multiple
ecosystems also illustrates this. If each ecosystem has its own database and
suppose there is a Rust TLS library with a vulnerability and a Go wrapper of
that library, then you'd have two entries: one in the Go database and one in the
Rust database. There's no need to try to put the Rust and Go versions into a
single entry. Both entries could mention the other in "aliases", and maybe
they'd both also list the same CVE in "aliases" as well. On the other hand if
the goal is to define a "one true entry" then obviously you do need to be able
to make the affected versions per-ecosystem, along with potentially most of the
other fields.

For the purpose of discussion, I assert that "one true entry" is still a
non-goal for this schema and that aggregators can easily separate out "affected
Rust versions" and "affected Go versions" from the two entries. I'm skeptical
about a single global database both because of the overhead of coordination (it
bogs down as more and more ecosystems get involved) and how much harder it makes
it to customize and experiment on a per-ecosystem basis. I think there's still a
lot to learn about what we want from these databases, and a more distributed,
federated model makes more sense to me.

Do people think that's a mistake? Does someone want to make the counter-argument
that we should expand the scope to being able to define the entries in a single
global database?

Thanks.

## Status - 2021-04-23

Affected versions. I added more explanatory text to the discussion of the
affected field, to make clear what is expected as far as ecosystem-specific
encodings of ranges. I also added a new `ECOSYSTEM` range type.

Non-unique database prefixes. I changed the discussion in "id, modified" to
handle the case of databases that decide to use identifiers drawn from some
larger space, such as a language that only issues CVE numbers, not its own
identifiers.

Multi-ecosystem vulnerabilities. There was an open issue, discussed at length in
the previous status update, about whether to be able to capture a vulnerability
in multiple ecosystems in a single report. As noted in the previous update,
attempting to do that seems like it introduces unnecessary coordination problems
while also calling into question literally every top-level field that might now
have to be duplicated for each ecosystem. That is, even the description may need
to be tailored for each ecosystem, meaning that the new multi-ecosystem format
ends up being a map from ecosystem to the current format. At that point, it’s
indistinguishable from multiple current-format records.

Also, it appears that even GHSA uses distinct entries for the same CVE from
different ecosystems. For example, CVE 2019-8331 in Bootstrap is both
https://github.com/advisories/GHSA-fxwm-579q-49qq (nuget) and
https://github.com/advisories/GHSA-wh77-3x4m-4q9g (npm).

Similarly, the example I happened to pick for NPM above was assigned
SNYK-JS-ELLIPTIC-1064899 but has the related entry
SNYK-JAVA-ORGWEBJARSNPM-1069836 for that code vendored into the Java world. 

I’ve resolved the open issue in favor of single-ecosystem entries rather than
multi-ecosystem entries. Following a suggestion from Robert Schultheis, I added
a "related" list next to "aliases" to capture this kind of close relationship.
I’ve updated the NPM example, which already listed SNYK-JS-ELLIPTIC-1064899 in
"aliases", to list SNYK-JAVA-ORGWEBJARSNPM-1069836 in "related".

Severity. Based on the discussion, removed severity as a top-level field (it is
too ill-specified and not generally interpretable). Databases can provide it as
a database-specific field instead.

Extra. Based on the discussion and general confusion about what belonged here,
split back into two fields: ecosystem-specific and database-specific.

References. Updated the examples to use the new objects with "type" and "url".
Based on that, added some new reference types.

My plan is to rewrite the italicized paragraph at the top of the doc on Monday
and then share the link publicly to gather more feedback from groups that have
not yet seen it.

## Status - 2021-08-05

The biggest change to the schema is our decision to support multiple packages
and ecosystems per entry. This is a reversal of our decision back in April (see
"Status - 2021-04-23" for our rationale).

This is primarily in the interests of supporting better interoperability with
other vulnerability schemas, such as the [CVE JSON
schema](https://github.com/CVEProject/cve-schema),
where multiple packages are supported in a single entry. We've
also been suggesting changes to the CVE schema as well for better
alignment
([1](https://github.com/CVEProject/cve-schema/issues/86),
 [2](https://github.com/CVEProject/cve-schema/issues/87),
 [3](https://github.com/CVEProject/cve-schema/issues/88),
 [4](https://github.com/CVEProject/cve-schema/issues/89)).

This is a breaking change, but we hope to make migration easier by renaming the
"affects" field to "affected" to allow existing consumers and producers of this
data to more easily handle old and new versions of entries.
