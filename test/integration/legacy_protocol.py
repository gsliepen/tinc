#!/usr/bin/env python3

"""Test legacy protocol support (tinc 1.0)."""

import typing as T

from testlib import check, cmd
from testlib.log import log
from testlib.proc import Tinc, Script
from testlib.test import Test

TIMEOUT = 2


def init(ctx: Test) -> T.Tuple[Tinc, Tinc]:
    """Initialize new test nodes."""
    foo, bar = ctx.node(), ctx.node()

    stdin = f"""
        init {foo}
        set Port 0
        set DeviceType dummy
        set Address localhost
        add Subnet 10.98.98.1
        set PingTimeout {TIMEOUT}
    """
    foo.cmd(stdin=stdin)
    foo.start()

    stdin = f"""
        init {bar}
        set Port 0
        set Address localhost
        set DeviceType dummy
        add Subnet 10.98.98.2
        set PingTimeout {TIMEOUT}
        set MaxTimeout {TIMEOUT}
    """
    bar.cmd(stdin=stdin)

    cmd.exchange(foo, bar)
    bar.cmd("add", "ConnectTo", foo.name)

    foo.add_script(bar.script_up)
    bar.add_script(foo.script_up)

    return foo, bar


def run_keys_test(foo: Tinc, bar: Tinc, empty: bool) -> None:
    """Check that EC public keys match the expected values."""
    bar.cmd("start")

    foo[bar.script_up].wait()
    bar[foo.script_up].wait()

    check.nodes(foo, 2)
    check.nodes(bar, 2)

    foo_bar, _ = foo.cmd("get", f"{bar.name}.Ed25519PublicKey", code=None)
    log.info('got key foo/bar "%s"', foo_bar)

    bar_foo, _ = bar.cmd("get", f"{foo.name}.Ed25519PublicKey", code=None)
    log.info('got key bar/foo "%s"', bar_foo)

    assert not foo_bar == empty
    assert not bar_foo == empty


with Test("foo 1.1, bar 1.1") as context:
    foo_node, bar_node = init(context)
    run_keys_test(foo_node, bar_node, empty=False)

with Test("foo 1.1, bar 1.0") as context:
    foo_node, bar_node = init(context)
    bar_node.cmd("set", "ExperimentalProtocol", "no")
    foo_node.cmd("del", f"{bar_node}.Ed25519PublicKey")
    bar_node.cmd("del", f"{foo_node}.Ed25519PublicKey")
    run_keys_test(foo_node, bar_node, empty=True)

with Test("bar 1.0 must not be allowed to connect") as context:
    foo_node, bar_node = init(context)
    bar_node.cmd("set", "ExperimentalProtocol", "no")

    bar_up = bar_node.add_script(Script.SUBNET_UP)
    bar_node.cmd("start")
    bar_up.wait()

    assert not foo_node[bar_node.script_up].wait(TIMEOUT * 2)
    check.nodes(foo_node, 1)
    check.nodes(bar_node, 1)
