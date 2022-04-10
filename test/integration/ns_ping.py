#!/usr/bin/env python3

"""Create two network namespaces and run ping between them."""

import subprocess as subp
import typing as T

from testlib import external as ext, util, template, cmd
from testlib.log import log
from testlib.proc import Tinc, Script
from testlib.test import Test

util.require_root()
util.require_command("ip", "netns", "list")
util.require_path("/dev/net/tun")

IP_FOO = "192.168.1.1"
IP_BAR = "192.168.1.2"
MASK = 24


def init(ctx: Test) -> T.Tuple[Tinc, Tinc]:
    """Initialize new test nodes."""
    foo, bar = ctx.node(), ctx.node()

    log.info("create network namespaces")
    assert ext.netns_add(foo.name)
    assert ext.netns_add(bar.name)

    log.info("initialize two nodes")

    stdin = f"""
        init {foo}
        set Port 0
        set Subnet {IP_FOO}
        set Interface {foo}
        set Address localhost
        set AutoConnect no
    """
    foo.cmd(stdin=stdin)
    foo.add_script(Script.TINC_UP, template.make_netns_config(foo.name, IP_FOO, MASK))
    foo.start()

    stdin = f"""
        init {bar}
        set Port 0
        set Subnet {IP_BAR}
        set Interface {bar}
        set Address localhost
        set AutoConnect no
    """
    bar.cmd(stdin=stdin)
    bar.add_script(Script.TINC_UP, template.make_netns_config(bar.name, IP_BAR, MASK))

    cmd.exchange(foo, bar)

    return foo, bar


def ping(namespace: str, ip_addr: str) -> int:
    """Send pings between two network namespaces."""
    log.info("pinging node from netns %s at %s", namespace, ip_addr)
    proc = subp.run(
        ["ip", "netns", "exec", namespace, "ping", "-W1", "-c1", ip_addr], check=False
    )

    log.info("ping finished with code %d", proc.returncode)
    return proc.returncode


with Test("ns-ping") as context:
    foo_node, bar_node = init(context)
    bar_node.cmd("start")

    log.info("waiting for nodes to come up")
    bar_node[Script.TINC_UP].wait()

    log.info("ping must not work when there is no connection")
    assert ping(foo_node.name, IP_BAR)

    log.info("add script foo/host-up")
    bar_node.add_script(foo_node.script_up)

    log.info("add ConnectTo clause")
    bar_node.cmd("add", "ConnectTo", foo_node.name)

    log.info("bar waits for foo")
    bar_node[foo_node.script_up].wait()

    log.info("ping must work after connection is up")
    assert not ping(foo_node.name, IP_BAR)
