#!/bin/sh

set -eux

dir="$1"
shift

flags=$(./.ci/conf.sh "$@")

# shellcheck disable=SC2086
meson setup "$dir" $flags

ninja -C "$dir"
