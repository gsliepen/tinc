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

  mkdir -p sanitizer /tmp/logs

  header "Running test flavor $flavor"

  autoreconf -fsi

  DISTCHECK_CONFIGURE_FLAGS=$(sh .ci/conf.sh "$@")
  export DISTCHECK_CONFIGURE_FLAGS

  # shellcheck disable=SC2086
  ./configure $DISTCHECK_CONFIGURE_FLAGS

  make -j"$(nproc)" all extra

  if [ "$(uname -s)" = Linux ]; then
    cmd=distcheck
  else
    cmd=check
  fi

  code=0
  make $cmd -j2 VERBOSE=1 || code=$?

  sudo tar -c -z -f "/tmp/logs/tests.$flavor.tar.gz" test/ sanitizer/

  return $code
}

case "$(uname -s)" in
Linux)
  if [ -n "${HOST:-}" ]; then
    # Needed for cross-compilation for 32-bit targets.
    export CPPFLAGS="${CPPFLAGS:-} -D_FILE_OFFSET_BITS=64"
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
  export CPPFLAGS="${CPPFLAGS:-} -I/usr/local/include -I$gcrypt/include -I$openssl/include -I$gcrypt/include"
  ;;
esac

case "$1" in
default)
  run_tests default
  ;;
nolegacy)
  run_tests nolegacy --disable-legacy-protocol
  ;;
gcrypt)
  run_tests gcrypt --with-libgcrypt
  ;;
*)
  bail "unknown test flavor $1"
  ;;
esac
