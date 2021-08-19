#!/bin/bash

set -euo pipefail

dir=$(realpath "$(dirname "$0")")

logs="$GITHUB_WORKSPACE/sanitizer"

case "$SANITIZER" in
undefined)
  flags='-fsanitize=integer -fsanitize=nullability'
  export UBSAN_OPTIONS="log_path=$logs/ubsan:print_stacktrace=1"
  ;;

address)
  flags='-fsanitize-address-use-after-scope -fsanitize=pointer-compare -fsanitize=pointer-subtract'
  export ASAN_OPTIONS="log_path=$logs/asan:detect_invalid_pointer_pairs=2:strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1"
  ;;

thread)
  flags=''
  export TSAN_OPTIONS="log_path=$logs/tsan"
  ;;

*)
  echo >&2 "unknown sanitizer $SANITIZER"
  exit 1
  ;;
esac

export CC='clang-12'
export CPPFLAGS='-DDEBUG'
export CFLAGS="-O0 -g -fsanitize=$SANITIZER -fno-omit-frame-pointer -fno-common -fsanitize-blacklist=$dir/ignore.txt $flags"

bash .ci/test/run.sh "$@"

# Check that the sanitizer has not created any log files.
# If it has, fail the job to notify the developer.
log_count=$(find "$logs" -type f -printf . | wc -c)

if [ "$log_count" != 0 ]; then
  echo "expected zero sanitizer logs, found $log_count"
  exit 1
fi
