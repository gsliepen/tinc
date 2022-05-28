#!/bin/bash

# Three nodes are initialized:
#   latest : created from the latest commit that triggered this CI job
#   tinc11 : from the latest tag in tinc 1.1 branch
#   tinc10 : from the latest commit in tinc 1.0 branch
#
# The latter two are configured by using import/export/exchange.
# Since tinc 1.0 doesn't support that, host configs are copied to its hosts directory.
# Then nodes are connected and some light testing is performed to make sure they work together.

set -euo pipefail

nodes='latest tinc11 tinc10'
total_nodes=3

declare -A refs=(
  [tinc10]='origin/master'
  [tinc11]="$(git describe --abbrev=0 --match='release-*')"
  [latest]='HEAD'
)

declare -A addr=(
  [tinc10]='192.168.1.1'
  [tinc11]='192.168.1.2'
  [latest]='192.168.1.3'
)

src=/usr/local/src
etc=/usr/local/etc

mkdir -p $src $etc

archive() {
  tar -caf /tmp/tests.tar.gz /usr/local/etc || true
}

header() {
  echo >&2 '################################################################################'
  echo >&2 "# $*"
  echo >&2 '################################################################################'
}

build_meson() {
  meson setup "$1" -D prefix="/opt/$1"
  meson install -C "$1"
}

build_autotools() {
  autoreconf -fsi
  ./configure --prefix="/opt/$1"
  make -j"$(nproc)"
  make install
}

build() {
  local ref="$1"
  header "Building tinc (ref $ref)"

  git clone "$PWD" "$src/$ref" -b "compat-$ref"
  pushd "$src/$ref"

  if [[ -f meson.build ]]; then
    build_meson "$ref"
  else
    build_autotools "$ref"
  fi

  popd
  mkdir -p "/opt/$ref/var/run"
}

wait_network() {
  local from="$1"
  local to="$2"
  local total=0

  while ! ip netns exec "$from" ping -W1 -c1 "${addr[$to]}" >/dev/null; do
    total=$((total + 1))

    if [[ total -gt 60 ]]; then
      echo >&2 "Network connection between $from and $to is not working"
      exit 1
    fi

    echo >&2 "Network isn't ready yet..."
    sleep 1
  done
}

test_network() {
  local from="$1"
  local to="$2"

  wait_network "$from" "$to"

  header "Sending data between $from and $to"

  ip netns exec "$from" \
    iperf3 --time 1 --client "${addr[$to]}"
}

test_sign_verify() {
  local signer="$1"
  local verifier="$2"
  local output="$etc/$signer/signed"

  header "Test signature verification between $signer and $verifier"

  "$signer" sign >"$output" <<<"text message for node $signer to sign"

  for peer in "$signer" '*'; do
    "$verifier" verify "$peer" "$output"
    "$verifier" verify "$peer" <"$output"
  done
}

test_node_status() {
  local node="$1"

  header "Checking node status for $node"

  reachable="$("$node" dump reachable nodes | wc -l)"
  echo >&2 "Node $node can reach $reachable nodes"

  [[ $reachable == "$total_nodes" ]]

  for peer in $nodes; do
    echo >&2 -n "$node info $peer: "
    "$node" info "$peer" | tee /dev/stderr | grep -E -q '(can reach itself|directly)'
  done
}

latest() {
  /opt/latest/sbin/tinc -c $etc/latest "$@"
}

tinc11() {
  /opt/tinc11/sbin/tinc -c $etc/tinc11 "$@"
}

header 'Creating branches'

for node in $nodes; do
  echo >&2 "    $node: $(git rev-parse "compat-$node")"
  git branch "compat-$node" "${refs[$node]}"
done

build tinc10
build tinc11
build latest

header 'Initializing node from the latest commit'

latest <<EOF
  init latest
  set Address localhost
  set Port 30000
  set Interface latest
  set Subnet ${addr[latest]}
  set Compression 0
  set LogLevel 5
EOF

header 'Initializing node from the latest tag'

tinc11 <<EOF
  init tinc11
  set Address localhost
  set Port 30001
  set Interface tinc11
  set Subnet ${addr[tinc11]}
  set Compression 3
  set LogLevel 5
EOF

header 'Initializing node for tinc 1.0'

mkdir -p $etc/tinc10/hosts

cat >$etc/tinc10/tinc.conf <<EOF
Name = tinc10
Interface = tinc10
Compression = 10
LogLevel = 5
EOF

cat >$etc/tinc10/hosts/tinc10 <<EOF
Address = localhost
Port = 30002
Subnet = ${addr[tinc10]}
EOF

/opt/tinc10/sbin/tincd -c $etc/tinc10 --generate-keys

trap archive EXIT INT TERM

header 'Creating network namespaces'

for ns in $nodes; do
  ip netns add "$ns"
done

header 'Creating network configuration scripts'

for node in $nodes; do
  tinc_up="$etc/$node/tinc-up"

  cat >"$tinc_up" <<EOF
#!/bin/bash
set -eu
ip link set dev $node netns $node
ip netns exec $node ip addr add ${addr[$node]}/24 dev $node
ip netns exec $node ip link set $node up
ip netns exec $node ip link set lo up
ip netns exec $node iperf3 --server --daemon
EOF

  chmod 755 "$tinc_up"
done

header 'Exchanging host files'

# Not all configs are copied to make sure 'peer exchange' is working
# tinc10 <--> latest <--> tinc11
latest export | tinc11 exchange | latest import
cp $etc/tinc10/hosts/tinc10 $etc/latest/hosts/
cp $etc/latest/hosts/latest $etc/tinc10/hosts/

header "Starting nodes"

for node in $nodes; do
  tincd="/opt/$node/sbin/tincd"
  echo >&2 "Starting node $node ($tincd)"

  "$tincd" --version

  "$tincd" \
    --config "$etc/$node" \
    --pidfile "$etc/$node/pid" \
    --logfile "$etc/$node/log" \
    --debug 5
done

header 'Running connectivity tests'

for client in $nodes; do
  for server in $nodes; do
    if [[ $client != "$server" ]]; then
      test_network "$client" "$server"
    fi
  done
done

test_node_status latest
test_node_status tinc11

test_sign_verify latest tinc11
test_sign_verify tinc11 latest
