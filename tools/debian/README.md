# Debian advisory converter (WIP)

## Prerequisites

Clone the following two repositories:
- https://salsa.debian.org/security-tracker-team/security-tracker.git
- https://salsa.debian.org/webmaster-team/webwml.git

`git` also has to be installed and on the `PATH`, 
used to read modified dates of files 

## Run converter

```
python convert_debian.py -o ./output path/to/webwml/ path/to/security-tracker-master/
```
