# GHSA to OSV converter.

## Usage

```bash
$ pipenv sync
$ pipenv shell
$ mkdir out
$ python3 dump_ghsa.py --token $GITHUB_TOKEN out
$ mkdir osv
$ python3 convert_ghsa.py -o osv out/*.json
```
