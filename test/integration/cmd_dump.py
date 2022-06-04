#!/usr/bin/env python3

"""Test dump commands."""

import subprocess as subp

from testlib import check
from testlib.log import log
from testlib.proc import Tinc
from testlib.test import Test

SUBNETS_FOO = ("10.0.0.0/16", "10.1.2.0/24")
SUBNETS_BAR = ("10.3.2.0/27", "fe80::/64")
SUBNETS_BROADCAST = len(
    (
        "ff:ff:ff:ff:ff:ff owner (broadcast)",
        "255.255.255.255 owner (broadcast)",
        "224.0.0.0/4 owner (broadcast)",
        "ff00::/8 owner (broadcast)",
    )
)
ONLINE_REQUESTS = (
    ("connections",),
    ("digraph",),
    ("edges",),
    ("foobar",),
    ("graph",),
    ("nodes",),
    ("reachable", "nodes"),
    ("subnets",),
)


def try_dot(src: str) -> None:
    """Try passing graph source through the dot binary, if it's present."""
    try:
        res = subp.run("dot", input=src, stdout=subp.PIPE, check=True, encoding="utf-8")
        check.true(res.stdout)
    except FileNotFoundError:
        pass


def run_offline_tests(command: str, foo: Tinc) -> None:
    """Run offline tests."""

    log.info("dump empty invitations")
    out, err = foo.cmd(command, "invitations")
    check.false(out)
    check.is_in("No outstanding invitations", err)

    for request in ONLINE_REQUESTS:
        log.info("dump online type %s", request)
        _, err = foo.cmd(command, *request, code=1)
        check.is_in("Could not open pid file", err)


def dump_pending_invitation(foo: Tinc, bar: Tinc) -> None:
    """Test dumping of pending invitations."""

    log.info("dump %s invitation", bar)
    out, _ = foo.cmd("dump", "invitations")
    check.lines(out, 1)
    file, node = out.strip().split(" ")
    check.true(file)
    check.equals(node, bar.name)


def run_unconnected_tests(foo: Tinc, bar: Tinc) -> None:
    """Run online tests with unconnected nodes."""

    log.info("dump invalid type")
    _, err = foo.cmd("dump", "foobar42", code=1)
    check.is_in("Unknown dump type", err)

    log.info("use 'reachable' with wrong command")
    _, err = foo.cmd("dump", "reachable", "edges", code=1)
    check.is_in("reachable' only supported for nodes", err)

    log.info("check for too many arguments")
    _, err = foo.cmd("dump", "edges", "please", code=1)
    check.is_in("Invalid number of arguments", err)

    log.info("dump unconnected edges")
    out, _ = foo.cmd("dump", "edges")
    check.lines(out, 0)

    log.info("dump unconnected subnets")
    out, _ = foo.cmd("dump", "subnets")
    check.lines(out, SUBNETS_BROADCAST + len(SUBNETS_FOO))
    for sub in SUBNETS_FOO:
        check.is_in(sub, out)

    log.info("dump unconnected connections")
    out, _ = foo.cmd("dump", "connections")
    check.lines(out, 1)
    check.is_in("<control>", out)

    log.info("%s knows about %s", foo, bar)
    out, _ = foo.cmd("dump", "nodes")
    check.lines(out, 2)
    check.is_in(f"{foo} id ", out)
    check.is_in(f"{bar} id ", out)

    log.info("%s can only reach itself", foo)
    out, _ = foo.cmd("dump", "reachable", "nodes")
    check.lines(out, 1)
    check.is_in(f"{foo} id ", out)


def run_connected_tests(foo: Tinc, bar: Tinc) -> None:
    """Run online tests with connected nodes."""

    log.info("dump connected edges")
    out, _ = foo.cmd("dump", "edges")
    check.lines(out, 2)
    check.is_in(f"{foo} to {bar}", out)
    check.is_in(f"{bar} to {foo}", out)

    log.info("dump connected connections")
    out, _ = foo.cmd("dump", "connections")
    check.lines(out, 2)
    check.is_in("<control> at ", out)
    check.is_in(f"{bar} at ", out)

    log.info("dump connected subnets")
    out, _ = foo.cmd("dump", "subnets")
    check.lines(out, SUBNETS_BROADCAST + len(SUBNETS_FOO) + len(SUBNETS_BAR))
    for sub in (*SUBNETS_FOO, *SUBNETS_BAR):
        check.is_in(sub, out)

    for kind in "graph", "digraph":
        log.info("dump %s", kind)
        out, _ = foo.cmd("dump", kind)
        check.is_in(f"{kind} {{", out)
        try_dot(out)

    log.info("dump connected nodes")
    for arg in (("nodes",), ("reachable", "nodes")):
        out, _ = foo.cmd("dump", *arg)
        check.lines(out, 2)
        check.is_in(f"{foo} id ", out)
        check.is_in(f"{bar} id ", out)


def run_tests(ctx: Test) -> None:
    """Run all tests."""

    foo, bar = ctx.node(init=True), ctx.node()

    log.info("set %s subnets", foo)
    for sub in SUBNETS_FOO:
        foo.cmd("add", "Subnet", sub)

    for command in "dump", "list":
        run_offline_tests(command, foo)

    log.info("start %s", foo)
    foo.start()

    log.info("invite %s", bar)
    url, _ = foo.cmd("invite", bar.name)
    url = url.strip()

    dump_pending_invitation(foo, bar)

    log.info("join %s and set subnets", bar)
    bar.cmd("join", url)
    bar.cmd("set", "DeviceType", "dummy")
    bar.cmd("set", "Port", "0")
    for sub in SUBNETS_BAR:
        bar.cmd("add", "Subnet", sub)

    run_unconnected_tests(foo, bar)

    log.info("start %s", bar)
    foo.add_script(bar.script_up)
    bar.cmd("start")
    foo[bar.script_up].wait()

    run_connected_tests(foo, bar)


with Test("run dump tests") as context:
    run_tests(context)
