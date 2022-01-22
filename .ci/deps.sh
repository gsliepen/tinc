#!/bin/sh

set -eu

deps_linux_alpine() {
  apk upgrade

  apk add \
    git binutils make autoconf automake gcc linux-headers diffutils texinfo \
    procps socat shadow sudo libgcrypt-dev \
    openssl-dev zlib-dev lzo-dev ncurses-dev readline-dev musl-dev lz4-dev vde2-dev
}

deps_linux_debian() {
  export DEBIAN_FRONTEND=noninteractive

  HOST=${HOST:-}

  if [ -n "$HOST" ]; then
    dpkg --add-architecture "$HOST"
  fi

  apt-get update
  apt-get upgrade -y

  apt-get install -y \
    git binutils make autoconf automake gcc diffutils sudo texinfo netcat-openbsd procps socat \
    zlib1g-dev:"$HOST" \
    libssl-dev:"$HOST" \
    liblzo2-dev:"$HOST" \
    liblz4-dev:"$HOST" \
    libncurses-dev:"$HOST" \
    libreadline-dev:"$HOST" \
    libgcrypt-dev:"$HOST" \
    libminiupnpc-dev:"$HOST" \
    libvdeplug-dev:"$HOST" \
    "$@"

  if [ -n "$HOST" ]; then
    apt-get install -y crossbuild-essential-"$HOST" qemu-user
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
    git binutils make autoconf automake gcc diffutils sudo texinfo netcat procps systemd \
    findutils socat lzo-devel zlib-devel lz4-devel ncurses-devel readline-devel libgcrypt-devel "$@"

  if yum info openssl11-devel; then
    yum install -y openssl11-devel
  else
    dnf install -y openssl-devel
  fi

  if yum info miniupnpc-devel; then
    yum install -y miniupnpc-devel
  fi
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
    ;;

  *) exit 1 ;;
  esac
}

deps_macos() {
  brew install coreutils netcat automake lzo lz4 miniupnpc libgcrypt openssl "$@"
  pip3 install --user compiledb
}

case "$(uname -s)" in
Linux) deps_linux "$@" ;;
Darwin) deps_macos "$@" ;;
*) exit 1 ;;
esac
