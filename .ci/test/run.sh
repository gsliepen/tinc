#!/bin/sh

set -eux

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

  ./.ci/build.sh "$@"

  if [ "${HOST:-}" = mingw ]; then
    echo >&2 "Integration tests cannot run under wine, skipping"
    return 0
  fi

  code=0
  meson test -C build --verbose || code=$?

  sudo tar -c -z -f "/tmp/logs/tests.$flavor.tar.gz" build/ sanitizer/

  return $code
}

case "$(uname -s)" in
MINGW* | Darwin) sudo() { "$@"; } ;;
esac

flavor=$1
shift

case "$flavor" in
default)
  run_tests default "$@"
  ;;
nolegacy)
  run_tests nolegacy -Dcrypto=nolegacy "$@"
  ;;
gcrypt)
  run_tests gcrypt -Dcrypto=gcrypt "$@"
  ;;
openssl3)
  if [ -d /opt/ssl3 ]; then
    run_tests openssl3 -Dpkg_config_path=/opt/ssl3/lib64/pkgconfig "$@"
  else
    echo >&2 "OpenSSL 3 not installed, skipping test"
  fi
  ;;
*)
  bail "unknown test flavor $1"
  ;;
esac
