#!/bin/bash

set -euxo pipefail

if ! rpm -qi openssl-devel; then
  exit 0
fi

find_tag() {
  git describe --always --tags --match='release-*' "$@"
}

spec=$HOME/rpmbuild/SPECS/tinc.spec
version=$(find_tag HEAD | sed 's/-/_/g')
version=${version//release_/}

export CONFIG_SHELL=bash

yum install -y rpmdevtools
rpmdev-setuptree

cp "$(dirname "$0")/tinc.spec" "$spec"
sed -i "s/__VERSION__/$version/" "$spec"

git clean -dfx
cp -a . ~/rpmbuild/BUILD

rpmbuild -bb "$spec"
