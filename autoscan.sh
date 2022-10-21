#!/bin/bash
# A shell script that scans all APKs against all rules

FILES="./rules/*"
for f in $FILES
do
  echo "Processing $f file..."
  python3 scan.py reports apk $f
done
