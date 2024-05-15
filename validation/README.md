# JSON Validator

This directory contains a JSON schema to validate OSV entries.

## Example Usage

(Any [validator](https://json-schema.org/implementations#validators) can be used, these are a couple that are known to work)

```
$ go run github.com/neilpa/yajsv@latest -s schema.json osv_to_test.json
```

```
$ pip install check-jsonschema
$ check-jsonschema --schemafile schema.json osv_to_test.json
```
