#!/bin/sh

set -eux

add_flag() {
  printf ' %s ' "$@"
}

conf_linux() {
  HOST="${HOST:-nonexistent}"
  if [ "$HOST" = mingw ]; then
    cross=".ci/cross/windows/amd64"
  else
    cross=".ci/cross/linux/$HOST"
  fi
  if [ -f "$cross" ]; then
    add_flag --cross-file "$cross"
  fi
  add_flag -Dminiupnpc=auto -Duml=true
}

conf_windows() {
  add_flag -Dminiupnpc=auto
}

conf_macos() {
  openssl=$(brew --prefix openssl)
  add_flag -Dminiupnpc=auto -Dpkg_config_path="$openssl/lib/pkgconfig"
}

add_flag -Dbuildtype=release "$@"

case "$(uname -s)" in
Linux) conf_linux ;;
MINGW*) conf_windows ;;
Darwin) conf_macos ;;
*) exit 1 ;;
esac
