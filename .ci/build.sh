#!/bin/sh

set -eux

flags=$(./.ci/conf.sh "$@")

# shellcheck disable=SC2086
meson setup build $flags

ninja -C build
