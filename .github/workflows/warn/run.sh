#!/bin/sh

set -eu

test -n "$CC"
export CFLAGS="${CFLAGS:-} -Werror"

result=0

check_warnings() {
  git clean -dfx

  autoreconf -fsi
  ./configure --enable-uml --enable-vde --enable-miniupnpc "$@"

  make -j"$(nproc)" all extra || result=$?
}

check_warnings
check_warnings --disable-legacy-protocol

exit $result
