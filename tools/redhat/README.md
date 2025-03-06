# Red Hat CSAF to OSV Converter

## Setup

This tool is installable via Pip using a git reference such as:

~~~
redhat-osv @ git+https://github.com/ossf/osv-schema@0cef5d4#egg=redhat_osv&subdirectory=tools/redhat
~~~

Dependency management is therefore split between `setup.py` and `Pipenv`. Runtime dependencies are declared in 
`setup.py` and installable by installing the project into a pipenv environment:

~~~
$ pipenv install -e .
~~~

## Usage

Needs to be run in a folder where the Red Hat CSAF documents to convert already exist. Files can be downloaded the [Red Hat Customer Portal Security Data section](https://access.redhat.com/security/data/csaf/v2/advisories/)
~~~
$ pipenv run python3 convert_redhat.py testdata/rhsa-2024_4546.json
~~~

OSV documents will be output in the `osv` directory by default. Override the default with the `--output_directory` option.

## Running Tests

Run the tests like so:

~~~
$ pipenv run python3 -m unittest redhat_osv/*_test.py
~~~

## How does it work?

Red Hat [Common Security Advisory Framework](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html) (CSAF) Advisories are made up of 3 sections, document, [product_tree](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#322-product-tree-property) and [vulnerabilities](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#323-vulnerabilities-property). How we use each section is converted to OSV format is explained below. A new CSAF Advisory is published each time a remediation for a security vulnerability in a Red Hat product is released. Red Hat will publish one advisory for each product affected by a vulnerability. However one advisory may remediate multiple vulnerabilities.

### What is converted?

The CSAF document is first represented as a CSAF object which holds references to vulnerabilities. Vulnerabilities, in turn hold references to [remediations](https://docs.oasis-open.org/csaf/csaf/v2.0/os/csaf-v2.0-os.html#32312-vulnerabilities-property---remediations). Remediations are a combination of the affected product information, including a [Common Product Enumeration](https://csrc.nist.gov/projects/security-content-automation-protocol/specifications/cpe) (CPE) Name, a component, a PURL and a fixed version. A component in this context is a Red Hat specific reference to the affected component, and refers to the same thing as the PURL. We need to store the component in the Remediation object so that we can relate it to PURL in the product_tree section of the CSAF advisory.

### How is it converted?

OSV records hold a set of [affected data](https://ossf.github.io/osv-schema/#affected-fields). Each affected data object holds references to packages and ranges.

[Packages](https://ossf.github.io/osv-schema/#affectedpackage-field) contain a name, and ecosystem which is also represented as a PURL. The `Red Hat` ecosystem is a translation of the CPE in the CSAF document with the `cpe/:[oa]:redhat` prefix replaced with `Red Hat`. Since CSAF advisories only identify the version of the package which was fixed, all previous versions of that package released in the corresponding product are considered affected. This is converted to a single [Event](https://ossf.github.io/osv-schema/#affectedrangesevents-fields) in OSV with an `introduced` value of `0` and a `fixed` equal to the `fixed_version` from the CSAF advisory.

OSV [references](https://ossf.github.io/osv-schema/#references-field) are a combination of the Red Hat Advisory, references from that advisory, and the vulnerability specific references in the CSAF document. While CSAF advisories always contain at least one CVE identifier for a vulnerability, the other entries in the OSV [related](https://ossf.github.io/osv-schema/#related-field) field are converted from the CSAF advisory vulnerability references.

