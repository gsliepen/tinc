#!/bin/sh

git describe --always --tags --match='release-*' "$@" | sed 's/release-//'
