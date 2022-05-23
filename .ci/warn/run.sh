#!/bin/bash

set -euo pipefail

test -n "$CC"

result=0

clang_tidy() {
  rm -f compile_commands.json
  ln -s "$1"/compile_commands.json .
  run-clang-tidy || result=$?
}

check_warnings() {
  flavor="$1"
  dir="${CC}_${flavor}"

  ./.ci/build.sh "$dir" -Dwerror=true || result=$?

  case "$CC" in
  clang*) clang_tidy "$dir" ;;
  esac
}

check_warnings default
check_warnings nolegacy
check_warnings gcrypt

exit $result
