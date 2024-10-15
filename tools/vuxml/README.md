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

```
Usage: convert_vuxml.py [-e ecosystem][-o output_directory] path/to/vuln.xml
```

#### Options

`-e`:
Set a specific ecosystem in the converted output (default: FreeBSD:ports)

`-o`:
Output directory to place the converted osv `.json` files

### Example

```
$ python3.9 convert_vuxml.py /usr/ports/security/vuxml/vuln.xml
```
