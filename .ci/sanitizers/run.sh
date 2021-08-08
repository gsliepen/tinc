#!/bin/bash

set -euo pipefail

logs="$GITHUB_WORKSPACE/sanitizer"
mkdir -p "$logs"

case "$SANITIZER" in
address)
  export ASAN_OPTIONS="log_path=$logs/asan:detect_invalid_pointer_pairs=2:strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1"
  ;;

thread)
  export TSAN_OPTIONS="log_path=$logs/tsan"
  ;;

undefined)
  export UBSAN_OPTIONS="log_path=$logs/ubsan:print_stacktrace=1"
  ;;

*)
  echo >&2 "unknown sanitizer $SANITIZER"
  exit 1
  ;;
esac

sudo --preserve-env=ASAN_OPTIONS,TSAN_OPTIONS,UBSAN_OPTIONS \
  make check VERBOSE=1

# Check that the sanitizer has not created any log files.
# If it has, fail the job to notify the developer.
log_count=$(find "$logs" -type f -printf . | wc -c)

if [ "$log_count" != 0 ]; then
  echo "expected zero sanitizer logs, found $log_count"
  exit 1
fi
