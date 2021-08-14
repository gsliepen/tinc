#!/bin/bash

set -euo pipefail

test -n "$CC"
export CFLAGS="${CFLAGS:-} -Werror"

result=0

check_warnings() {
  git clean -dfx

  autoreconf -fsi
  # shellcheck disable=SC2046
  ./configure $(sh .ci/conf.sh)
  make -j"$(nproc)" all extra || result=$?
}

check_warnings
check_warnings --disable-legacy-protocol

exit $result
