#!/bin/bash

set -euo pipefail

. /etc/os-release

bail() {
  echo >&2 "$@"
  exit 1
}

find_tag() {
  git describe --always --tags --match='release-*' "$@"
}

apt-get install -y devscripts git-buildpackage dh-make

export USER=${USER:-$(whoami)}

os="$ID-$VERSION_ID"
templates=$(dirname "$0")/debian

git clean -dfx

# get latest tag name
curr=$(find_tag HEAD)
[[ -z $curr ]] && bail 'could not determine release version'

# get previous tag name
prev=$(find_tag "$curr"^)
[[ -z $curr ]] && bail 'could not determine previous release version'

# strip release prefix to get the current version number
version=${curr//release-/}

# prepare a new debian directory
dh_make --yes --single --createorig --copyright gpl2 --packagename "tinc_$version-$os"

# write all commit messages between two most recent tags to the changelog
gbp dch --since "$prev" --ignore-branch --spawn-editor=never --release

# replace placeholders with files copied from https://packages.debian.org/experimental/tinc
cp "$templates/"* debian/

# remove useless READMEs created by dh_make
rm -f debian/README.*

dpkg-buildpackage -d -us -uc
mv ../*.deb .
