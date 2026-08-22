# EUVD to OSV converter

## Require


The Linux shell tools are standalone and require `bash`, `curl`, `jq`, and GNU
`date`.


```bash
apt install curl
apt install jq
```

## Usage

```bash
mkdir out
./dump_euvd.sh out
mkdir osv
./convert_euvd.sh -o osv out/*.json
```

You can restrict the dump with query parameters accepted by the EUVD search API:

```bash
./dump_euvd.sh --vendor nodejs --fromDate 2026-01-01 --toDate 2026-31-12 out

```

## Unit Test

```bash
./convert_euvd_test.sh
```


