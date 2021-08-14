#!/bin/bash

set -euo pipefail

find_tag() {
  git describe --always --tags --match='release-*' "$@"
}

# CentOS 7 has OpenSSL 1.1 installed in a non-default location.
if [ -d /usr/include/openssl11 ]; then
  set -- "$@" --with-openssl-include=/usr/include/openssl11
fi

if [ -d /usr/lib64/openssl11 ]; then
  set -- "$@" --with-openssl-lib=/usr/lib64/openssl11
fi

spec=$HOME/rpmbuild/SPECS/tinc.spec
configure=$(sh .ci/conf.sh)

version=$(find_tag HEAD | sed 's/-/_/g')
version=${version//release_/}

export CONFIG_SHELL=bash

yum install -y rpmdevtools
rpmdev-setuptree

cp "$(dirname "$0")/tinc.spec" "$spec"
sed -i "s/__VERSION__/$version/" "$spec"
sed -i "s#__CONFIGURE_ARGS__#$configure#" "$spec"

git clean -dfx
autoreconf -fsi
cp -a . ~/rpmbuild/BUILD

rpmbuild -bb "$spec"
