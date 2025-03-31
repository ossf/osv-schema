# Guiding principles

Changes to the OSV (Open Source Vulnerability) schema are evaluated against
several core principles:

## 1. Focus on Core Use Cases

The primary goal driving the OSV schema's design is to **enable software
developers to accurately identify and remediate all known vulnerabilities
within their applications' open source dependencies**.

To achieve this, the schema specifically supports two key use cases:
1. For Vulnerability **Databases**: Make it easy for any vulnerability database
   to adopt and export the format, so that we have comprehensive coverage.
2. For Vulnerability **Scanners**: Create a format that vulnerability scanners
   can use to produce **accurate** and **actionable** vulnerability scanning
   results.

This focus means that there may be some use cases of vulnerability data that
are out of scope, such as:
- Historical analysis of vulnerability trends.
- Tracking metadata about vulnerabilities that may be interesting but otherwise
  not useful for automatic vulnerability matching and remediation (e.g.
  individual timelines of vulnerabilities, or detailed relationship graphs
  between vulnerabilities).

## 2. Simplicity

A well-defined use case allows the schema to remain concise and minimal. This
simplicity makes the schema easier for consumers (like scanners) to understand
and easier for producers (like databases) to adopt.

Each field must serve a distinct purpose directly linked to the core use cases.
There must also be a practical way for vulnerability data producers to supply the
data for each field. Aspirational fields, which vulnerability databases cannot
realistically populate, should be avoided.

## 3. Correctness and Consistency

OSV schema fields must promote data correctness and consistency.

Fields require unambiguous rules for encoding values, including specifics like
casing and formatting.

Where the schema refers to specific software ecosystems (e.g., package
managers), its rules must align precisely with that ecosystem's specifications.
For instance, package names and version ordering for the "PyPI" ecosystem must
adhere strictly to PyPI's official rules.

## 4. Prioritizing Open Source

While the OSV schema can represent vulnerabilities in closed-source software,
its primary focus and design considerations prioritize open source software
ecosystems.

## 5. Federated Database Model

The OSV schema promotes a distributed model of "home" vulnerability databases,
maintained by the relevant communities or organizations.

For example, the Go community maintains a database using the `GO-` prefix,
while the Rust community maintains one using `RUSTSEC-`.

This means vulnerability records are ideally owned and published by the most
relevant upstream source for that ecosystem.

Consequently, metadata originating by definition from separate, centralized
authorities (like EPSS scores or CISA KEV status), doesn't belong directly
within the core OSV record itself, as it's not authored by the record's "home"
database.

## 6. Backwards Compatibility

The OSV schema is considered stable. Future versions must maintain backwards
compatibility, ensuring that:

- Existing clients supporting an older version of the schema don’t have to update
  their behaviour to consume records targeting newer versions.
- Clients that support a newer version of the schema don’t have to account for
  older versions of the schema.

In practice, this means:

- Fields are never removed.
- The meaning or interpretation of existing fields can be broadened, but never
  changed in a way that breaks older clients.
- Clients must be able to safely ignore fields or values introduced in newer
  schema versions that they don't understand.

This commitment of backwards compatibility means that there is a large cost
associated with adding a new field to the schema. While it may seem simple to
add a new field, its permanence increases the schema's complexity over time.
