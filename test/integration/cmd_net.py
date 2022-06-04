#!/usr/bin/env python3

"""Test network control commands."""

from testlib import check, cmd
from testlib.log import log
from testlib.proc import Tinc
from testlib.test import Test


def init(ctx: Test) -> Tinc:
    """Initialize a node."""
    return ctx.node(init="set AutoConnect no")


def test_network(foo: Tinc) -> None:
    """Test command 'network'."""

    _, err = foo.cmd("network", "foo", "bar", code=1)
    check.is_in("Too many arguments", err)

    _, err = foo.cmd("network", "foo./", code=1)
    check.is_in("Invalid character in netname", err)

    _, err = foo.cmd("network", "foo.<")
    check.is_in("unsafe character in netname", err)


def run_tests(foo: Tinc, bar: Tinc) -> None:
    """Run tests."""

    log.info("start nodes")
    foo.start()
    bar.start()
    check.nodes(foo, 1)

    log.info("test failing commands")
    _, err = foo.cmd("connect", code=1)
    check.is_in("Invalid number of arguments", err)

    _, err = foo.cmd("connect", "foo", "bar", code=1)
    check.is_in("Invalid number of arguments", err)

    _, err = foo.cmd("connect", f"{bar}@", code=1)
    check.is_in("Invalid name for node", err)

    log.info("connect nodes")
    foo.add_script(bar.script_up)
    cmd.exchange(foo, bar)

    # Implement REQ_CONNECT and update this
    log.info("test connect")
    _, err = foo.cmd("connect", bar.name, code=1)
    check.is_in("Could not connect to", err)

    log.info("connect nodes")
    foo.cmd("add", "ConnectTo", bar.name)
    foo.cmd("retry")
    foo[bar.script_up].wait()
    check.nodes(foo, 2)

    log.info("disconnect nodes")
    foo.add_script(bar.script_down)
    foo.cmd("disconnect", bar.name)
    foo[bar.script_down].wait()
    check.nodes(foo, 1)

    log.info("second disconnect must fail")
    _, err = foo.cmd("disconnect", bar.name, code=1)
    check.is_in("Could not disconnect", err)

    log.info("retry connections")
    foo.cmd("retry")
    foo[bar.script_up].wait()
    check.nodes(foo, 2)

    log.info("purge old connections")
    bar.cmd("stop")
    foo[bar.script_down].wait()
    foo.cmd("purge")

    for command, result in ("nodes", 1), ("edges", 0), ("subnets", 4):
        out, _ = foo.cmd("dump", command)
        check.lines(out, result)

    test_network(foo)


with Test("run network tests") as context:
    run_tests(init(context), init(context))
