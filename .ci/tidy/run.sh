#!/bin/sh

set -eu

./.ci/build.sh "$@"

# Which paths to ignore.
paths='src/solaris src/mingw src/gcrypt'

case "$(uname -s)" in
Linux)
  paths="$paths src/bsd"
  ;;

FreeBSD)
  paths="$paths src/linux src/bsd/tunemu.c"
  ;;

Darwin)
  paths="$paths src/linux src/vde_device.c"
  ;;

*) exit 1 ;;
esac

path_filters=''
for path in $paths; do
  path_filters=" $path_filters ! ( -path $path -prune ) "
done

echo >&2 "Running clang-tidy without $paths"

# This is fine, our paths are relative and do not contain any whitespace.
# shellcheck disable=SC2086
find src \
  $path_filters \
  -name '*.c' \
  -exec clang-tidy -p build --header-filter='.*' '{}' +
