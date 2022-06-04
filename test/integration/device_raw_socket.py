#!/usr/bin/env python3

"""Test raw socket device support."""

import sys
import subprocess as subp

from testlib import check, util
from testlib.log import log
from testlib.const import EXIT_SKIP
from testlib.proc import Script
from testlib.test import Test
from testlib.external import veth_add, move_dev, ping

util.require_root()
util.require_command("ip", "link")

FAKE_DEV = "cqhqdr7knaLzYeMSdy"

IP_NETNS = "10.198.96.1"
IP_HOST = "10.198.96.2"


def test_device_raw_socket(ctx: Test) -> None:
    """Test raw socket device."""

    foo = ctx.node(init="set DeviceType raw_socket")
    foo_log = foo.sub("log")

    log.info("test with a bad Interface")
    _, err = foo.cmd("start", "-o", f"Interface={FAKE_DEV}", code=1)
    if "Raw socket device not supported" in err:
        sys.exit(EXIT_SKIP)
    check.is_in(f"Can't find interface {FAKE_DEV}", err)

    log.info("create a veth pair")
    dev0, dev1 = util.random_string(10), util.random_string(10)
    veth_add(dev0, dev1)

    log.info("configure the veth pair")
    move_dev(dev1, dev1, f"{IP_NETNS}/30")
    subp.run(["ip", "addr", "add", f"{IP_HOST}/30", "dev", dev0], check=True)
    subp.run(["ip", "link", "set", dev0, "up"], check=True)

    log.info("set Interface and Device")
    foo.cmd("set", "Interface", dev0)
    foo.cmd("set", "Device", f"dev_{dev0}")
    foo.add_script(Script.TINC_UP)

    log.info("start tincd")
    _, err = foo.cmd("start", "--logfile", foo_log, "-d10")
    check.is_in(f"dev_{dev0} is a raw_socket", err)

    log.info("send some data to tincd interface")
    foo[Script.TINC_UP].wait()
    assert ping(IP_NETNS)

    log.info("stop tincd")
    foo.add_script(Script.TINC_DOWN)
    foo.cmd("stop")
    foo[Script.TINC_DOWN].wait()

    log.info("check that tincd received some data")
    check.in_file(foo_log, "Writing packet of")
    check.in_file(foo_log, "Read packet of")


with Test("test raw socket device") as context:
    test_device_raw_socket(context)
