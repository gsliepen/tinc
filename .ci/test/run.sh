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
  sudo chown -R "${USER:-$(whoami)}" .

  header "Running test flavor $flavor"

  autoreconf -fsi
  # shellcheck disable=SC2046
  ./configure $(sh .ci/conf.sh "$@")
  make -j"$(nproc)" all extra

  code=0
  make check -j2 VERBOSE=1 || code=$?

  mkdir -p /tmp/logs
  sudo tar -c -z -f "/tmp/logs/tests.$flavor.tar.gz" test/

  return $code
}

echo "system name $(uname -s)"
echo "full $(uname -a)"
echo "o $(uname -o)"

case "$(uname -s)" in
Linux)
  if [ -n "${HOST:-}" ]; then
    # Needed for cross-compilation for 32-bit targets.
    export CPPFLAGS='-D_FILE_OFFSET_BITS=64'
  fi
  ;;

MINGW*)
  # No-op.
  sudo() { "$@"; }
  ;;

Darwin)
  nproc() { sysctl -n hw.ncpu; }
  gcrypt=$(brew --prefix libgcrypt)
  openssl=$(brew --prefix openssl)
  export CPPFLAGS="-I/usr/local/include -I$gcrypt/include -I$openssl/include -I$gcrypt/include"
  ;;
esac

case "$1" in
default)
  run_tests default
  ;;
nolegacy)
  run_tests nolegacy --disable-legacy-protocol
  ;;
*)
  bail "unknown test flavor $1"
  ;;
esac
