# GHSA to OSV converter

## Setup

```bash
$ pipenv sync
$ pipenv shell
```

## Usage

```bash
$ mkdir out
$ python3 dump_ghsa.py --token $GITHUB_TOKEN out
$ mkdir osv
$ python3 convert_ghsa.py -o osv out/*.json
```

## Unit Test

```bash
$ python3 -m unittest *_test.py
```
