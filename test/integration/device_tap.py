#!/usr/bin/env python3

"""Test TAP device support."""

import typing as T

from testlib import check, util, cmd
from testlib.log import log
from testlib.proc import Script, Tinc
from testlib.test import Test
from testlib.external import netns_add, netns_exec, ping

util.require_root()
util.require_command("ip", "netns", "list")
util.require_path("/dev/net/tun")

IP_FOO = "10.0.0.1"
IP_BAR = "10.0.0.2"
IP_DUMMY = "10.0.0.3"

ARP_WORKS = {
    "router": False,
    "hub": True,
    "switch": True,
}


def make_up(node: str, address: str) -> str:
    """Create a network configuration script."""
    return f"""
    import subprocess as subp
    subp.run(['ip', 'link', 'set', 'dev', '{node}', 'netns', '{node}'], check=True)
    subp.run(['ip', 'netns', 'exec', '{node}', 'ip', 'addr', 'add', 'dev', '{node}', '{address}/24'], check=True)
    subp.run(['ip', 'netns', 'exec', '{node}', 'ip', 'link', 'set', '{node}', 'up'], check=True)
    """


def init(ctx: Test, mode: str) -> T.Tuple[Tinc, Tinc]:
    """Configure nodes."""

    stdin = f"""
        set DeviceType tap
        add Subnet {IP_FOO}
        set Mode {mode}
    """
    foo = ctx.node(init=stdin)
    foo.cmd("set", "Interface", foo.name)
    netns_add(foo.name)

    stdin = f"""
        set DeviceType tap
        add Subnet {IP_BAR}
        set Mode {mode}
    """
    bar = ctx.node(init=stdin)
    bar.cmd("set", "Interface", bar.name)
    netns_add(bar.name)

    return foo, bar


def run_tests(ctx: Test, mode: str) -> None:
    """Test BindToAddress or ListenAddress."""

    foo, bar = init(ctx, mode)

    log.info("add tinc-up scripts")
    foo.add_script(Script.TINC_UP, make_up(foo.name, IP_FOO))
    bar.add_script(Script.TINC_UP, make_up(bar.name, IP_BAR))

    log.info("start nodes and wait for them to connect")
    cmd.connect(foo, bar)

    log.info("test ICMP")
    assert ping(IP_FOO, bar.name)

    log.info("create a dummy device for sending ARP requests")
    netns_exec(bar.name, "ip", "link", "add", "dummy0", "type", "dummy", check=True)
    netns_exec(bar.name, "ip", "addr", "add", IP_DUMMY, "dev", "dummy0", check=True)
    netns_exec(bar.name, "ip", "link", "set", "dummy0", "up", check=True)

    log.info("test ARP with Mode %s", mode)
    proc = netns_exec(foo.name, "arping", "-c1", IP_DUMMY)
    check.equals(ARP_WORKS[dev_mode], proc.returncode == 0)


for dev_mode in "switch", "hub", "router":
    with Test(f"test TAP device ({dev_mode})") as context:
        run_tests(context, dev_mode)
