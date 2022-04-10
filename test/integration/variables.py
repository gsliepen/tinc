#!/usr/bin/env python3

"""Test tinc and tincd configuration variables."""

import typing as T
from pathlib import Path

from testlib import check, cmd
from testlib.log import log
from testlib.proc import Tinc
from testlib.test import Test

bad_subnets = (
    "1.1.1",
    "1:2:3:4:5:",
    "1:2:3:4:5:::6",
    "1:2:3:4:5:6:7:8:9",
    "256.256.256.256",
    "1:2:3:4:5:6:7:8.123",
    "1:2:3:4:5:6:7:1.2.3.4",
    "a:b:c:d:e:f:g:h",
    "1.1.1.1/0",
    "1.1.1.1/-1",
    "1.1.1.1/33",
    "1::/0",
    "1::/-1",
    "1::/129",
    ":" * 1024,
)


def init(ctx: Test) -> T.Tuple[Tinc, Tinc]:
    """Initialize new test nodes."""
    node0, node1 = ctx.node(), ctx.node()

    log.info("initialize node %s", node0)
    stdin = f"""
        init {node0}
        set Port 0
        set Address localhost
        get Name
    """
    out, _ = node0.cmd(stdin=stdin)
    check.equals(node0.name, out.strip())

    return node0, node1


with Test("test case sensitivity") as context:
    foo, bar = init(context)

    foo.cmd("set", "Mode", "switch")
    check.equals("switch", cmd.get(foo, "Mode"))
    check.equals("switch", cmd.get(foo, "mOdE"))

    foo.cmd("set", "Mode", "router")
    check.equals("router", cmd.get(foo, "MoDE"))
    check.equals("router", cmd.get(foo, "mode"))

    foo.cmd("set", "Mode", "Switch")
    check.equals("Switch", cmd.get(foo, "mode"))

    foo.cmd("del", "Mode", "hub", code=1)
    foo.cmd("del", "Mode", "switch")
    mode, _ = foo.cmd("get", "Mode", code=1)
    check.false(mode)

with Test("single Mode variable is permitted") as context:
    foo, bar = init(context)
    foo.cmd("add", "Mode", "switch")
    foo.cmd("add", "Mode", "hub")
    check.equals("hub", cmd.get(foo, "Mode"))

with Test("test addition/deletion of multivalued variables") as context:
    foo, bar = init(context)
    for i in range(1, 4):
        sub = f"{i}.{i}.{i}.{i}"
        foo.cmd("add", "Subnet", sub)
        foo.cmd("add", "Subnet", sub)
    check.equals(["1.1.1.1", "2.2.2.2", "3.3.3.3"], cmd.get(foo, "Subnet").splitlines())

    log.info("delete one subnet")
    foo.cmd("del", "Subnet", "2.2.2.2")
    check.equals(["1.1.1.1", "3.3.3.3"], cmd.get(foo, "Subnet").splitlines())

    log.info("delete all subnets")
    foo.cmd("del", "Subnet")
    subnet, _ = foo.cmd("get", "Subnet", code=1)
    check.false(subnet)

with Test("cannot get/set server variables using node.variable syntax") as context:
    foo, bar = init(context)
    name, _ = foo.cmd("get", f"{foo.name}.Name", code=1)
    check.false(name)
    foo.cmd("set", f"{foo.name}.Name", "fake", code=1)

with Test("get/set host variables for other nodes") as context:
    foo, bar = init(context)
    foo_bar = foo.sub("hosts", bar.name)
    Path(foo_bar).touch(0o644, exist_ok=True)

    bar_pmtu = f"{bar.name}.PMTU"
    foo.cmd("add", bar_pmtu, "1")
    foo.cmd("add", bar_pmtu, "2")
    check.equals("2", cmd.get(foo, bar_pmtu))

    bar_subnet = f"{bar.name}.Subnet"
    for i in range(1, 4):
        sub = f"{i}.{i}.{i}.{i}"
        foo.cmd("add", bar_subnet, sub)
        foo.cmd("add", bar_subnet, sub)

    check.equals(
        ["1.1.1.1", "2.2.2.2", "3.3.3.3"], cmd.get(foo, bar_subnet).splitlines()
    )

    foo.cmd("del", bar_subnet, "2.2.2.2")
    check.equals(["1.1.1.1", "3.3.3.3"], cmd.get(foo, bar_subnet).splitlines())

    foo.cmd("del", bar_subnet)
    subnet, _ = foo.cmd("get", bar_subnet, code=1)
    check.false(subnet)

with Test("cannot get/set variables for nodes with invalid names") as context:
    foo, bar = init(context)
    Path(foo.sub("hosts", "fake-node")).touch(0o644, exist_ok=True)
    foo.cmd("set", "fake-node.Subnet", "1.1.1.1", code=1)

    log.info("cannot set obsolete variables unless forced")
    foo.cmd("set", "PrivateKey", "12345", code=1)
    foo.cmd("--force", "set", "PrivateKey", "67890")
    check.equals("67890", cmd.get(foo, "PrivateKey"))

    foo.cmd("del", "PrivateKey")
    key, _ = foo.cmd("get", "PrivateKey", code=1)
    check.false(key)

    log.info("cannot set/add malformed Subnets")
    for subnet in bad_subnets:
        log.info("testing subnet %s", subnet)
        foo.cmd("add", "Subnet", subnet, code=1)

    subnet, _ = foo.cmd("get", "Subnet", code=1)
    check.false(subnet)
