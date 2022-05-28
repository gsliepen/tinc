#!/bin/bash

# Fetch and build
#   muon (a C reimplementation of the meson build system),
#   samurai (a C reimplementation of the ninja build tool),
# and then use both to build tinc.

set -euo pipefail

git_samurai=https://github.com/michaelforney/samurai
git_muon=https://git.sr.ht/~lattis/muon
prefix=/opt/tinc_muon

header() {
  echo >&2 '################################################################################'
  echo >&2 "# $*"
  echo >&2 '################################################################################'
}

header 'Try to make sure Python is missing'
python --version && exit 1
python3 --version && exit 1

header 'Fetch and build samurai'

git clone --depth=1 $git_samurai ~/samurai
pushd ~/samurai
make -j"$(nproc)"
make install
popd

header 'Fetch and build muon'

git clone --depth=1 $git_muon ~/muon
pushd ~/muon
./bootstrap.sh build
./build/muon setup build
samu -C build
./build/muon -C build install
popd

header 'Setup build directory'
muon setup -D prefix=$prefix -D systemd=disabled build_muon
samu -C build_muon

header 'Install tinc'
muon -C build_muon install

header 'Run smoke tests'
$prefix/sbin/tinc --version
$prefix/sbin/tincd --version
$prefix/sbin/tinc -c /tmp/muon_node <<EOF
init muon
set DeviceType dummy
set Address localhost
set Port 0
start
EOF
