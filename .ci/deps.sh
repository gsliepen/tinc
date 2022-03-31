#!/bin/sh

set -eu

deps_linux_alpine() {
  apk upgrade

  apk add \
    git binutils meson pkgconf gcc linux-headers shadow sudo libgcrypt-dev texinfo gzip \
    openssl-dev zlib-dev lzo-dev ncurses-dev readline-dev musl-dev lz4-dev vde2-dev cmocka-dev
}

deps_linux_debian_mingw() {
  apt-get install -y \
    mingw-w64 mingw-w64-tools \
    wine wine-binfmt \
    libgcrypt-mingw-w64-dev \
    "$@"
}

deps_linux_debian_linux() {
  if [ -n "$HOST" ]; then
    dpkg --add-architecture "$HOST"
  fi

  apt-get update

  apt-get install -y \
    binutils make gcc \
    zlib1g-dev:"$HOST" \
    libssl-dev:"$HOST" \
    liblzo2-dev:"$HOST" \
    liblz4-dev:"$HOST" \
    libncurses-dev:"$HOST" \
    libreadline-dev:"$HOST" \
    libgcrypt-dev:"$HOST" \
    libminiupnpc-dev:"$HOST" \
    libvdeplug-dev:"$HOST" \
    libcmocka-dev:"$HOST" \
    "$@"

  if [ -n "$HOST" ]; then
    apt-get install -y crossbuild-essential-"$HOST" qemu-user
  else
    linux_openssl3
  fi
}

deps_linux_debian() {
  export DEBIAN_FRONTEND=noninteractive

  apt-get update
  apt-get upgrade -y
  apt-get install -y git pkgconf sudo texinfo

  HOST=${HOST:-}
  if [ "$HOST" = mingw ]; then
    deps_linux_debian_mingw "$@"
  else
    deps_linux_debian_linux "$@"
  fi

  . /etc/os-release

  # Debian Buster ships an old version of meson (0.49).
  # MinGW cross-compilation requires something newer than 0.55 that ships in Bullseye,
  # or it fails when looking for dependencies in the OpenSSL wrap.
  if [ "${ID:-}/${VERSION_CODENAME:-}" = debian/buster ] || [ "$HOST" = mingw ]; then
    apt-get install -y python3 python3-pip ninja-build
    pip3 install meson
  else
    apt-get install -y meson
  fi
}

deps_linux_rhel() {
  if [ "$ID" != fedora ]; then
    yum install -y epel-release

    if type dnf; then
      dnf install -y 'dnf-command(config-manager)'
      dnf config-manager --enable powertools
    fi
  fi

  yum upgrade -y

  yum install -y \
    git binutils make meson pkgconf gcc sudo texinfo-tex systemd perl-IPC-Cmd \
    lzo-devel zlib-devel lz4-devel ncurses-devel readline-devel libgcrypt-devel "$@"

  if yum info openssl11-devel; then
    yum install -y openssl11-devel
  else
    dnf install -y openssl-devel
  fi

  if yum info miniupnpc-devel; then
    yum install -y miniupnpc-devel
  fi
}

linux_openssl3() {
  if [ -n "${SKIP_OPENSSL3:-}" ]; then
    echo >&2 "skipping openssl3 installation in this job"
    return
  fi

  src=/usr/local/src/openssl
  ssl3=/opt/ssl3

  mkdir -p $src

  git clone --depth 1 --branch openssl-3.0.2 https://github.com/openssl/openssl $src
  cd $src

  ./Configure --prefix=$ssl3 --openssldir=$ssl3
  make -j"$(nproc)"
  make install_sw

  if [ -f /etc/ld.so.conf ]; then
    echo $ssl3/lib64 >>/etc/ld.so.conf
    ldconfig -v
  else
    ldconfig -v $ssl3/lib64
  fi

  cd -
}

deps_linux() {
  . /etc/os-release

  case "$ID" in
  alpine)
    deps_linux_alpine "$@"
    ;;

  debian | ubuntu)
    deps_linux_debian "$@"
    ;;

  centos | almalinux | fedora)
    deps_linux_rhel "$@"
    linux_openssl3
    ;;

  *) exit 1 ;;
  esac
}

deps_macos() {
  brew install lzo lz4 miniupnpc libgcrypt openssl meson "$@"
}

case "$(uname -s)" in
Linux) deps_linux "$@" ;;
Darwin) deps_macos "$@" ;;
*) exit 1 ;;
esac
