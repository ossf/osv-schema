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
$ pipenv run convert_redhat testdata/rhsa-2024_4546.json
~~~

OSV documents will be output in the `osv` directory by default. Override the default with the `--output_directory` option.

## Running Tests

Run the tests like so:

~~~
$ pipenv run python3 -m unittest redhat_osv/*_test.py
~~~