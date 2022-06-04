#!/usr/bin/env python3

"""Test supported and unsupported compression levels."""

import os
import signal
import sys
import multiprocessing.connection as mpc
import subprocess as subp
import time
import typing as T

from testlib import external as ext, cmd, path, check, util
from testlib.log import log
from testlib.proc import Script, Tinc, Feature
from testlib.test import Test
from testlib.template import make_netns_config

IP_FOO = "192.168.1.1"
IP_BAR = "192.168.1.2"
MASK = 24

CONTENT = "zHgfHEzRsKPU41rWoTzmcxxxUGvjfOtTZ0ZT2S1GezL7QbAcMGiLa8i6JOgn59Dq5BtlfbZj"


def run_receiver() -> None:
    """Run server that receives data it prints it to stdout."""
    with mpc.Listener((IP_FOO, 0), family="AF_INET") as listener:
        port = listener.address[1]
        sys.stdout.write(f"{port}\n")
        sys.stdout.flush()

        with listener.accept() as conn:
            data = conn.recv()
            print(data, sep="", flush=True)


def run_sender() -> None:
    """Start client that reads data from stdin and sends it to server."""
    port = int(os.environ["PORT"])

    for _ in range(5):
        try:
            with mpc.Client((IP_FOO, port)) as client:
                client.send(CONTENT)
            return
        except OSError as ex:
            log.warning("could not connect to receiver", exc_info=ex)
            time.sleep(1)

    log.error("failed to send data, terminating")
    os.kill(0, signal.SIGTERM)


def get_levels(features: T.Container[Feature]) -> T.Tuple[T.List[int], T.List[int]]:
    """Get supported compression levels."""
    log.info("getting supported compression levels")

    levels: T.List[int] = []
    bogus: T.List[int] = []

    for comp, lvl_min, lvl_max in (
        (Feature.COMP_ZLIB, 1, 9),
        (Feature.COMP_LZO, 10, 11),
        (Feature.COMP_LZ4, 12, 12),
    ):
        lvls = range(lvl_min, lvl_max + 1)
        if comp in features:
            levels += lvls
        else:
            bogus += lvls

    log.info("supported compression levels: %s", levels)
    log.info("unsupported compression levels: %s", bogus)

    return levels, bogus


def init(ctx: Test) -> T.Tuple[Tinc, Tinc]:
    """Initialize new test nodes."""
    foo, bar = ctx.node(addr=IP_FOO), ctx.node(addr=IP_BAR)

    stdin = f"""
        init {foo}
        set Port 0
        set Address {foo.address}
        set Subnet {foo.address}
        set Interface {foo}
        set Address localhost
    """
    foo.cmd(stdin=stdin)
    assert ext.netns_add(foo.name)
    foo.add_script(Script.TINC_UP, make_netns_config(foo.name, foo.address, MASK))

    stdin = f"""
        init {bar}
        set Port 0
        set Address {bar.address}
        set Subnet {bar.address}
        set Interface {bar}
        set ConnectTo {foo}
    """
    bar.cmd(stdin=stdin)
    assert ext.netns_add(bar.name)
    bar.add_script(Script.TINC_UP, make_netns_config(bar.name, bar.address, MASK))
    foo.add_script(Script.SUBNET_UP)

    log.info("start %s and exchange configuration", foo)
    foo.start()
    cmd.exchange(foo, bar)

    return foo, bar


def test_valid_level(foo: Tinc, bar: Tinc) -> None:
    """Test that supported compression level works correctly."""
    while True:
        env = foo[Script.SUBNET_UP].wait().env
        if env.get("SUBNET") == bar.address:
            break

    log.info("start receiver in netns")
    with subp.Popen(
        ["ip", "netns", "exec", foo.name, path.PYTHON_PATH, __file__, "--recv"],
        stdout=subp.PIPE,
        encoding="utf-8",
    ) as receiver:
        assert receiver.stdout
        port = receiver.stdout.readline().strip()

        log.info("start sender in netns")
        with subp.Popen(
            ["ip", "netns", "exec", bar.name, path.PYTHON_PATH, __file__, "--send"],
            env={**dict(os.environ), "PORT": port},
        ):
            recv = receiver.stdout.read()
            log.info('received %d bytes: "%s"', len(recv), recv)

    check.success(receiver.wait())
    check.equals(CONTENT, recv.rstrip())


def test_bogus_level(node: Tinc) -> None:
    """Test that unsupported compression level fails to start."""
    tincd = node.tincd()
    _, stderr = tincd.communicate()
    check.failure(tincd.returncode)
    check.is_in("Bogus compression level", stderr)


def run_tests() -> None:
    """Run all tests."""
    with Test("get supported levels") as ctx:
        node = ctx.node()
        levels, bogus = get_levels(node.features)

    with Test("valid levels") as ctx:
        foo, bar = init(ctx)
        for level in levels:
            for node in foo, bar:
                node.cmd("set", "Compression", str(level))
            bar.cmd("start")
            test_valid_level(foo, bar)
            bar.cmd("stop")

    with Test("test bogus levels") as ctx:
        node = ctx.node()
        for level in bogus:
            node.cmd("set", "Compression", str(level))
            test_bogus_level(node)


last = sys.argv[-1]

if last == "--recv":
    run_receiver()
elif last == "--send":
    run_sender()
else:
    util.require_root()
    util.require_command("ip", "netns", "list")
    util.require_path("/dev/net/tun")
    run_tests()
