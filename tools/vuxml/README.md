# VuXML advisory converter

This is relevant to FreeBSD's ports, and possibly any other project using VuXML
in order to track vulnerabilities.

## Prerequisites

Clone the following repository:
- https://git.freebsd.org/ports.git

Install the following packages or modules:
- vuxml
- python-lxml

## Running the converter

### Usage

From VuXML to OSV format:

```
Usage: convert_vuxml.py [-e ecosystem][-o output_directory] path/to/vuln.xml
```

Where the VuXML vulnerabilities are either provided in a sequence of JSON data
on the standard output, or output to individual files in the output directory.

From OSV format to VuXML:

```
Usage: convert_osv.py [-o output_file] path/to/osv.json...
```

Where the OSV files provided are consolidated into a single VuXML file.

#### Options

`-e`:
Set a specific ecosystem in the converted output to OSV files (default:
FreeBSD:ports)

`-o`:
Output directory to place the converted OSV `.json` files (the directory must
exist and have write permissions), or output filename where to write the
converted VuXML file.

### Example

```
$ python3.9 convert_vuxml.py /usr/ports/security/vuxml/vuln.xml
$ python3.9 convert_osv.py 002432c8-ef6a-11ea-ba8f-08002728f74c.json
```
