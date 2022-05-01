#!/bin/sh

set -eu

flavor=$1

cd tinc

meson setup "$flavor" -D crypto="$flavor" -D miniupnpc=auto

meson test -C "$flavor" --verbose
