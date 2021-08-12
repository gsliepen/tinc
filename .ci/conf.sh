#!/bin/sh

set -eu

add_flag() {
  printf ' %s ' "$@"
}

conf_linux() {
  . /etc/os-release

  if type rpm >&2; then
    # CentOS 7 has OpenSSL 1.1 installed in a non-default location.
    if [ -d /usr/include/openssl11 ]; then
      add_flag --with-openssl-include=/usr/include/openssl11
    fi

    if [ -d /usr/lib64/openssl11 ]; then
      add_flag --with-openssl-lib=/usr/lib64/openssl11
    fi

    # RHEL 8 does not ship miniupnpc.
    if rpm -q miniupnpc-devel >&2; then
      add_flag --enable-miniupnpc
    fi
  else
    # vde2 is available everywhere except the RHEL family.
    add_flag --enable-vde
  fi

  # Cross-compilation.
  if [ -n "${HOST:-}" ]; then
    case "$HOST" in
    armhf) triplet=arm-linux-gnueabihf ;;
    mips) triplet=mips-linux-gnu ;;
    *) exit 1 ;;
    esac

    add_flag --host="$triplet"
  fi

  add_flag --enable-uml "$@"
}

conf_windows() {
  add_flag \
    --enable-miniupnpc \
    --disable-readline \
    --with-curses-include=/mingw64/include/ncurses \
    "$@"
}

conf_macos() {
  add_flag \
    --with-openssl="$(brew --prefix openssl)" \
    --with-miniupnpc="$(brew --prefix miniupnpc)" \
    --with-libintl-prefix="$(brew --prefix gettext)" \
    --enable-tunemu \
    --enable-miniupnpc \
    "$@"
}

case "$(uname -s)" in
Linux) conf_linux "$@" ;;
MINGW*) conf_windows "$@" ;;
Darwin) conf_macos "$@" ;;
*) exit 1 ;;
esac
