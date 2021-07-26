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
    sudo pkill -TERM -x "$name" || true
    sudo pkill -KILL -x "$name" || true
  done

  sudo git clean -dfx
  sudo chown -R build:build .

  header "Running test flavor $flavor"

  # CentOS 7 has OpenSSL 1.1 installed in a non-default location.
  if test -d /usr/include/openssl11; then
    set -- "$@" --with-openssl-include=/usr/include/openssl11
  fi

  if test -d /usr/lib64/openssl11; then
    set -- "$@" --with-openssl-lib=/usr/lib64/openssl11
  fi

  autoreconf -fsi
  ./configure "$@"
  make -j"$(nproc)"

  code=0
  make check -j2 VERBOSE=1 || code=$?

  sudo tar -c -z -f "/tmp/tests.$flavor.tar.gz" test/

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
