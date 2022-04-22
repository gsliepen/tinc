#!/usr/bin/env python3

"""Test splicing connection between tinc peers."""

import os
import subprocess as subp
import typing as T

from testlib import check, cmd, path
from testlib.log import log
from testlib.proc import Tinc, Script
from testlib.test import Test
from testlib.feature import SANDBOX_LEVEL


def init(ctx: Test, *options: str) -> T.Tuple[Tinc, Tinc]:
    """Initialize new test nodes."""
    custom = os.linesep.join(options)
    log.info('init two nodes with options "%s"', custom)

    foo, bar = ctx.node(), ctx.node()

    stdin = f"""
        init {foo}
        set Port 0
        set DeviceType dummy
        set Address localhost
        set AutoConnect no
        set Subnet 10.96.96.1
        set Sandbox {SANDBOX_LEVEL}
        {custom}
    """
    foo.cmd(stdin=stdin)

    stdin = f"""
        init {bar}
        set Port 0
        set Address localhost
        set DeviceType dummy
        set AutoConnect no
        set Subnet 10.96.96.2
        set Sandbox {SANDBOX_LEVEL}
        {custom}
    """
    bar.cmd(stdin=stdin)

    foo.add_script(Script.SUBNET_UP)
    bar.add_script(Script.SUBNET_UP)

    foo.start()
    bar.start()

    log.info("exchange host configs")
    cmd.exchange(foo, bar)

    return foo, bar


def splice(foo: Tinc, bar: Tinc, protocol: str) -> subp.Popen:
    """Start splice between nodes."""
    args = [
        path.SPLICE_PATH,
        foo.name,
        "localhost",
        str(foo.port),
        bar.name,
        "localhost",
        str(bar.port),
        protocol,
    ]
    log.info("splice with args %s", args)
    return subp.Popen(args)


def test_splice(ctx: Test, protocol: str, *options: str) -> None:
    """Splice connection and check that it fails."""
    log.info("no splicing allowed (%s)", protocol)
    foo, bar = init(ctx, *options)

    log.info("waiting for subnets to come up")
    foo[Script.SUBNET_UP].wait()
    bar[Script.SUBNET_UP].wait()

    splice_proc = splice(foo, bar, protocol)
    try:
        check.nodes(foo, 1)
        check.nodes(bar, 1)
    finally:
        splice_proc.kill()


with Test("sptps") as context:
    test_splice(context, "17.7")

with Test("legacy") as context:
    test_splice(context, "17.0", "set ExperimentalProtocol no")
