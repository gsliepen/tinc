#!/bin/bash

set -euo pipefail

test -n "$CC"

result=0

check_warnings() {
  git clean -dfx
  ./.ci/build.sh build -Dwerror=true "$@" || result=$?
}

check_warnings
check_warnings -Dcrypto=nolegacy

exit $result
