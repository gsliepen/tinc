#!/bin/bash

set -euo pipefail

dir=$(realpath "$(dirname "$0")")

case "$SANITIZER" in
undefined)
  flags='-fsanitize=integer -fsanitize=nullability'
  ;;

address)
  flags='-fsanitize-address-use-after-scope -fsanitize=pointer-compare -fsanitize=pointer-subtract'
  ;;

*)
  flags=''
  ;;
esac

export CPPFLAGS='-DDEBUG'
export CFLAGS="-O0 -g -fsanitize=$SANITIZER -fno-omit-frame-pointer -fno-common -fsanitize-blacklist=$dir/ignore.txt $flags"

autoreconf -fsi
./configure --enable-{uml,vde,miniupnpc}
make -j"$(nproc)" all
