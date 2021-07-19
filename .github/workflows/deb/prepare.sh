#!/bin/bash

set -euo pipefail

bail() {
  echo >&2 "$@"
  exit 1
}

find_tag() {
  git describe --abbrev=0 --always --tags --match='release-*' "$@"
}

templates=.github/workflows/deb/debian

# get latest tag name
curr=$(find_tag HEAD)
[[ -z $curr ]] && bail 'could not determine release version'

# get previous tag name
prev=$(find_tag "$curr"^)
[[ -z $curr ]] && bail 'could not determine previous release version'

# strip release prefix to get the current version number
version=${curr//release-/}

# prepare a new debian directory
dh_make --yes --single --createorig --copyright gpl2 --packagename "tinc_$version-$JOB_DISTRIBUTION"

# write all commit messages between two most recent tags to the changelog
gbp dch --since "$prev" --ignore-branch --spawn-editor=never --release

# replace placeholders with files copied from https://packages.debian.org/experimental/tinc
cp "$templates/"* debian/

# remove useless READMEs created by dh_make
rm -f debian/README.*
