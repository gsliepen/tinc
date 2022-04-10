#!/usr/bin/env python3

"""Check that basic functionality works (tincd can be started and stopped)."""

from testlib.test import Test
from testlib.proc import Tinc
from testlib.log import log
from testlib.script import Script
from testlib import check


def init(ctx: Test) -> Tinc:
    """Initialize new test nodes."""
    node = ctx.node()
    node.add_script(Script.TINC_UP)
    stdin = f"""
        init {node}
        set Address localhost
        set Port 0
        set DeviceType dummy
    """
    node.cmd(stdin=stdin)
    return node


def test(ctx: Test, *flags: str) -> None:
    """Run tests with flags."""
    log.info("init new node")
    node = init(ctx)

    log.info('starting tincd with flags "%s"', " ".join(flags))
    tincd = node.tincd(*flags)

    log.info("waiting for tinc-up script")
    node[Script.TINC_UP].wait()

    log.info("stopping tincd")
    node.cmd("stop")

    log.info("checking tincd exit code")
    check.equals(0, tincd.wait())


with Test("foreground mode") as context:
    test(context, "-D")

with Test("background mode") as context:
    test(context)
