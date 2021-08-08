#!/bin/sh

set -eu

build_linux() {
  . /etc/os-release

  case "$ID" in
  debian | ubuntu)
    bash .ci/package/deb/build.sh
    ;;
  almalinux | centos | fedora)
    bash .ci/package/rpm/build.sh
    ;;
  esac
}

case "$(uname -s)" in
Linux)
  build_linux
  ;;
MINGW*)
  bash .ci/package/win/build.sh
  ;;
esac
