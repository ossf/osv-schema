# JSON Validator

This directory contains a JSON schema to validate OSV entries.

## Usage

```
$ go run github.com/neilpa/yajsv@latest -s schema.json osv_to_test.json
```

```
$ pip install check-jsonschema
$ check-jsonschema --schemafile schema.json osv_to_test.json
```
