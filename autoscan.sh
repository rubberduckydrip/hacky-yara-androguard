#!/bin/bash
# A shell script that scans all APKs against all rules

find . -name '*.yar' -or -name '*.yara' |
while read in; do
    python3 scan.py reports apk "$in"
done
