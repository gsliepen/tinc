#!/bin/sh

set -ex

echo [STEP] Initialize test library

# Paths to compiled executables

# realpath on FreeBSD fails if the path does not exist.
realdir() {
  [ -e "$1" ] || mkdir -p "$1"
  if type realpath >/dev/null; then
    realpath "$1"
  else
    readlink -f "$1"
  fi
}

# Exit status list
# shellcheck disable=SC2034
EXIT_FAILURE=1
# shellcheck disable=SC2034
EXIT_SKIP_TEST=77

# The list of the environment variables that tinc injects into the scripts it calls.
# shellcheck disable=SC2016
TINC_SCRIPT_VARS='$NETNAME,$NAME,$DEVICE,$IFACE,$NODE,$REMOTEADDRESS,$REMOTEPORT,$SUBNET,$WEIGHT,$INVITATION_FILE,$INVITATION_URL,$DEBUG'

# Test directories

# Reuse script name if it was passed in an env var (when imported from tinc scripts).
if [ -z "$SCRIPTNAME" ]; then
  SCRIPTNAME=$(basename "$0")
fi

# Network names for tincd daemons.
net1=$SCRIPTNAME.1
net2=$SCRIPTNAME.2
net3=$SCRIPTNAME.3

# Configuration/pidfile directories for tincd daemons.
DIR_FOO=$(realdir "$PWD/$net1")
DIR_BAR=$(realdir "$PWD/$net2")
DIR_BAZ=$(realdir "$PWD/$net3")

# Register helper functions

# Alias gtimeout to timeout if it exists.
if type gtimeout >/dev/null; then
  timeout() { gtimeout "$@"; }
fi

# As usual, BSD tools require special handling, as they do not support -i without a suffix.
# Note that there must be no space after -i, or it won't work on GNU sed.
sed_cmd() {
  sed -i.orig "$@"
}

# Are the shell tools provided by busybox?
is_busybox() {
  timeout --help 2>&1 | grep -q -i busybox
}

# busybox timeout returns 128 + signal number (which is TERM by default)
if is_busybox; then
  # shellcheck disable=SC2034
  EXIT_TIMEOUT=$((128 + 15))
else
  # shellcheck disable=SC2034
  EXIT_TIMEOUT=124
fi

# Is this msys2?
is_windows() {
  test "$(uname -o)" = Msys
}

# Are we running on a CI server?
is_ci() {
  test "$CI"
}

# Dump error message and exit with an error.
bail() {
  echo >&2 "$@"
  exit 1
}

# Remove carriage returns to normalize strings on Windows for easier comparisons.
rm_cr() {
  tr -d '\r'
}

if is_windows; then
  normalize_path() { cygpath --mixed -- "$@"; }
else
  normalize_path() { echo "$@"; }
fi

# Executes whatever is passed to it, checking that the resulting exit code is non-zero.
must_fail() {
  if "$@"; then
    bail "expected a non-zero exit code"
  fi
}

# Executes the passed command and checks two conditions:
#   1. it must exit successfully (with code 0)
#   2. its output (stdout + stderr) must include the substring from the first argument (ignoring case)
# usage: expect_msg 'expected message' command --with --args
expect_msg() {
  message=$1
  shift

  if ! output=$("$@" 2>&1); then
    bail 'expected 0 exit code'
  fi

  if ! echo "$output" | grep -q -i "$message"; then
    bail "expected message '$message'"
  fi
}

# The reverse of expect_msg. We cannot simply wrap expect_msg with must_fail
# because there should be a separate check for tinc exit code.
fail_on_msg() {
  message=$1
  shift

  if ! output=$("$@" 2>&1); then
    bail 'expected 0 exit code'
  fi

  if echo "$output" | grep -q -i "$message"; then
    bail "unexpected message '$message'"
  fi
}

# Like expect_msg, but the command must fail with a non-zero exit code.
# usage: must_fail_with_msg 'expected message' command --with --args
must_fail_with_msg() {
  message=$1
  shift

  if output=$("$@" 2>&1); then
    bail "expected a non-zero exit code"
  fi

  if ! echo "$output" | grep -i -q "$message"; then
    bail "expected message '$message'"
  fi
}

# Is the legacy protocol enabled?
with_legacy() {
  tincd foo --version | grep -q legacy_protocol
}

# Are we running with EUID 0?
is_root() {
  test "$(id -u)" = 0
}

# Executes whatever is passed to it, checking that the resulting exit code is equal to the first argument.
expect_code() {
  expected=$1
  shift

  code=0
  "$@" || code=$?

  if [ $code != "$expected" ]; then
    bail "wrong exit code $code, expected $expected"
  fi
}

# wc -l on mac prints whitespace before the actual number.
# This is simplest cross-platform alternative without that behavior.
count_lines() {
  awk 'END{ print NR }'
}

# Calls compiled tinc, passing any supplied arguments.
# Usage: tinc { foo | bar | baz } --arg1 val1 "$args"
tinc() {
  peer=$1
  shift

  case "$peer" in
  foo) "$TINC_PATH" -n "$net1" --config="$DIR_FOO" --pidfile="$DIR_FOO/pid" "$@" ;;
  bar) "$TINC_PATH" -n "$net2" --config="$DIR_BAR" --pidfile="$DIR_BAR/pid" "$@" ;;
  baz) "$TINC_PATH" -n "$net3" --config="$DIR_BAZ" --pidfile="$DIR_BAZ/pid" "$@" ;;
  *) bail "invalid command [[$peer $*]]" ;;
  esac
}

# Calls compiled tincd, passing any supplied arguments.
# Usage: tincd { foo | bar | baz } --arg1 val1 "$args"
tincd() {
  peer=$1
  shift

  case "$peer" in
  foo) "$TINCD_PATH" -n "$net1" --config="$DIR_FOO" --pidfile="$DIR_FOO/pid" --logfile="$DIR_FOO/log" -d5 "$@" ;;
  bar) "$TINCD_PATH" -n "$net2" --config="$DIR_BAR" --pidfile="$DIR_BAR/pid" --logfile="$DIR_BAR/log" -d5 "$@" ;;
  baz) "$TINCD_PATH" -n "$net3" --config="$DIR_BAZ" --pidfile="$DIR_BAZ/pid" --logfile="$DIR_BAZ/log" -d5 "$@" ;;
  *) bail "invalid command [[$peer $*]]" ;;
  esac
}

# Start the specified tinc daemon.
# usage: start_tinc { foo | bar | baz }
start_tinc() {
  peer=$1
  shift

  case "$peer" in
  foo) tinc "$peer" start --logfile="$DIR_FOO/log" -d5 "$@" ;;
  bar) tinc "$peer" start --logfile="$DIR_BAR/log" -d5 "$@" ;;
  baz) tinc "$peer" start --logfile="$DIR_BAZ/log" -d5 "$@" ;;
  *) bail "invalid peer $peer" ;;
  esac
}

# Stop all tinc clients.
stop_all_tincs() {
  (
    # In case these pid files are mangled.
    set +e
    [ -f "$DIR_FOO/pid" ] && tinc foo stop
    [ -f "$DIR_BAR/pid" ] && tinc bar stop
    [ -f "$DIR_BAZ/pid" ] && tinc baz stop
    true
  )
}

# Checks that the number of reachable nodes matches what is expected.
# usage: require_nodes node_name expected_number
require_nodes() {
  echo >&2 "Check that we're able to reach tincd"
  test "$(tinc "$1" pid | count_lines)" = 1

  echo >&2 "Check the number of reachable nodes for $1 (expecting $2)"
  actual="$(tinc "$1" dump reachable nodes | count_lines)"

  if [ "$actual" != "$2" ]; then
    echo >&2 "tinc $1: expected $2 reachable nodes, got $actual"
    exit 1
  fi
}

peer_directory() {
  peer=$1
  case "$peer" in
  foo) echo "$DIR_FOO" ;;
  bar) echo "$DIR_BAR" ;;
  baz) echo "$DIR_BAZ" ;;
  *) bail "invalid peer $peer" ;;
  esac
}

# This is an append-only log of all scripts executed by all peers.
script_runs_log() {
  echo "$(peer_directory "$1")/script-runs.log"
}

# Create tincd script. If it fails, it kills the test script with SIGTERM.
# usage: create_script { foo | bar | baz } { tinc-up | host-down | ... } 'script content'
create_script() {
  peer=$1
  script=$2
  shift 2

  # This is the line that we should start from when reading the script execution log while waiting
  # for $script from $peer. It is a poor man's hash map to avoid polluting tinc's home directory with
  # "last seen" files. There seem to be no good solutions to this that are compatible with all shells.
  line_var=$(next_line_var "$peer" "$script")

  # We must reassign it here in case the script is recreated.
  # shellcheck disable=SC2229
  read -r "$line_var" <<EOF
1
EOF

  # Full path to the script.
  script_path=$(peer_directory "$peer")/$script

  # Full path to the script execution log (one for each peer).
  script_log=$(script_runs_log "$peer")
  printf '' >"$script_log"

  # Script output is redirected into /dev/null. Otherwise, it ends up
  # in tinc's output and breaks things like 'tinc invite'.
  cat >"$script_path" <<EOF
#!/bin/sh
(
  cd "$PWD" || exit 1
  SCRIPTNAME="$SCRIPTNAME" . "$TESTLIB_PATH"
  $@
  echo "$script,\$$,$TINC_SCRIPT_VARS" >>"$script_log"
) >/dev/null 2>&1 || kill -TERM $$
EOF

  chmod u+x "$script_path"

  if is_windows; then
    echo "@$MINGW_SHELL '$script_path'" >"$script_path.cmd"
  fi
}

# Returns the name of the variable that contains the line number
# we should read next when waiting on $script from $peer.
# usage: next_line_var foo host-up
next_line_var() {
  peer=$1
  script=$(echo "$2" | sed 's/[^a-zA-Z0-9]/_/g')
  printf "%s" "next_line_${peer}_${script}"
}

# Waits for `peer`'s script `script` to finish `count` number of times.
# usage: wait_script { foo | bar | baz } { tinc-up | host-up | ... } [count=1]
wait_script() {
  peer=$1
  script=$2
  count=$3

  if [ -z "$count" ] || [ "$count" -lt 1 ]; then
    count=1
  fi

  # Find out the location of the log and how many lines we should skip
  # (because we've already seen them in previous invocations of wait_script
  # for current $peer and $script).
  line_var=$(next_line_var "$peer" "$script")

  # eval is the only solution supported by POSIX shells.
  # https://github.com/koalaman/shellcheck/wiki/SC3053
  #   1. $line_var expands into 'next_line_foo_hosts_bar_up'
  #   2. the name is substituted and the command becomes 'echo "$next_line_foo_hosts_bar_up"'
  #   3. the command is evaluated and the line number is assigned to $line
  line=$(eval "echo \"\$$line_var\"")

  # This is the file that we monitor for script execution records.
  script_log=$(script_runs_log "$peer")

  # Starting from $line, read until $count matches are found.
  # Print the number of the last matching line and exit.
  # GNU tail 2.82 and newer terminates by itself when the pipe breaks.
  # To support other tails we do an explicit `kill`.
  # FIFO is useful here because otherwise it's difficult to determine
  # which tail process should be killed. We could stick them in a process
  # group by enabling job control, but this results in weird behavior when
  # running tests in parallel on some interactive shells
  # (e.g. when /bin/sh is symlinked to dash).
  fifo=$(mktemp)
  rm -f "$fifo"
  mkfifo "$fifo"

  # This weird thing is required to support old versions of ksh on NetBSD 8.2 and the like.
  (tail -n +"$line" -f "$script_log" >"$fifo") &

  new_line=$(
    sh -c "
      grep -n -m $count '^$script,' <'$fifo'
    " | awk -F: 'END { print $1 }'
  )

  # Try to stop the background tail, ignoring possible failure (some tails
  # detect EOF, some don't, so it may have already exited), but do wait on
  # it (which is required at least by old ksh).
  kill $! || true
  wait || true
  rm -f "$fifo"

  # Remember the next line number for future reference. We'll use it if
  # wait_script is called again with same $peer and $script.
  read -r "${line_var?}" <<EOF
$((line + new_line))
EOF
}

# Cleanup after running each script.
cleanup() {
  (
    set +ex

    if command -v cleanup_hook 2>/dev/null; then
      echo >&2 "Cleanup hook found, calling..."
      cleanup_hook
    fi

    stop_all_tincs
  ) || true
}

# If we're on a CI server, the test requires superuser privileges to run, and we're not
# currently a superuser, try running the test as one and fail if it doesn't work (the
# system must be configured to provide passwordless sudo for our user).
require_root() {
  if is_root; then
    return
  fi
  if is_ci; then
    echo "root is required for test $SCRIPTNAME, but we're a regular user; elevating privileges..."
    if ! command -v sudo 2>/dev/null; then
      bail "please install sudo and configure passwordless auth for user $USER"
    fi
    if ! sudo --preserve-env --non-interactive true; then
      bail "sudo is not allowed or requires a password for user $USER"
    fi
    exec sudo --preserve-env "$@"
  else
    # Avoid these kinds of surprises outside CI. Just skip the test.
    echo "root is required for test $SCRIPTNAME, but we're a regular user; skipping"
    exit "$EXIT_SKIP_TEST"
  fi
}

# Generate path to current shell which can be used from Windows applications.
if is_windows; then
  MINGW_SHELL=$(normalize_path "$SHELL")
fi

# This was called from a tincd script. Skip executing commands with side effects.
[ -n "$NAME" ] && return

echo [STEP] Check for leftover tinc daemons and test directories

# Cleanup leftovers from previous runs.
stop_all_tincs

rm -rf "$DIR_FOO" "$DIR_BAR" "$DIR_BAZ"

# Register cleanup function so we don't have to call it everywhere
# (and failed scripts do not leave stray tincd running).
trap cleanup EXIT INT TERM
