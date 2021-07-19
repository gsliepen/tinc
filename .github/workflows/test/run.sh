#!/bin/sh

set -eu

bail() {
  echo >&2 "@"
  exit 1
}

header() {
  echo '################################################################################'
  echo "# $*"
  echo '################################################################################'
}

run_tests() {
  flavor="$1"
  shift

  header "Cleaning up leftovers from previous runs"

  for name in tinc tincd; do
    pkill -TERM -x "$name" || true
    pkill -KILL -x "$name" || true
  done

  git clean -dfx

  header "Running test flavor $flavor"

  autoreconf -fsi
  ./configure "$@"
  make -j"$(nproc)"

  code=0
  make check -j2 VERBOSE=1 || code=$?

  tar -c -z -f "/tmp/tests.$flavor.tar.gz" test/

  return $code
}

# GitHub Checkout action supports git 2.18+.
# If we're running in a container with an older version,
# create our own local repository to make `git clean` work.
if ! [ -e .git ]; then
  git init
  git add .
fi

case "$1" in
default)
  run_tests default ''
  ;;
nolegacy)
  run_tests nolegacy --disable-legacy-protocol
  ;;
*)
  bail "unknown test flavor $1"
  ;;
esac
