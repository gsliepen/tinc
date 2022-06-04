#!/usr/bin/env python3

"""Test recent address cache."""

import os
import typing as T
import shutil

from testlib import check
from testlib.log import log
from testlib.proc import Tinc, Script
from testlib.test import Test


def init(ctx: Test) -> T.Tuple[Tinc, Tinc]:
    """Create test node."""
    bar = ctx.node()
    foo = ctx.node(init="set AutoConnect no")
    return foo, bar


def connect_nodes(foo: Tinc, bar: Tinc) -> None:
    """Start second node and wait for connection."""
    log.info("connect nodes")
    bar.cmd("start")
    bar[foo.script_up].wait()
    foo[bar.script_up].wait()


def run_tests(ctx: Test) -> None:
    """Run tests."""
    foo, bar = init(ctx)

    log.info("cache directory must exist after init")
    check.dir_exists(foo.sub("cache"))

    foo.add_script(Script.TINC_UP)
    foo.add_script(Script.INVITATION_ACCEPTED)
    foo.start()

    log.info("invite %s to %s", bar, foo)
    invite, _ = foo.cmd("invite", bar.name)
    invite = invite.strip()

    log.info("join %s to %s", bar, foo)
    bar.cmd("join", invite)

    log.info("cache directory must exist after join")
    check.dir_exists(bar.sub("cache"))

    log.info("invitee address must be cached after invitation is accepted")
    foo[Script.INVITATION_ACCEPTED].wait()
    check.file_exists(foo.sub(f"cache/{bar}"))
    os.remove(foo.sub(f"cache/{bar}"))

    log.info("configure %s", bar)
    bar.cmd("set", "DeviceType", "dummy")
    bar.cmd("set", "Port", "0")

    log.info("add host-up scripts")
    foo.add_script(bar.script_up)
    bar.add_script(foo.script_up)

    connect_nodes(foo, bar)

    log.info("%s must cache %s's public address", bar, foo)
    check.file_exists(bar.sub(f"cache/{foo}"))

    log.info("%s must not cache %s's outgoing address", foo, bar)
    assert not os.path.exists(foo.sub(f"cache/{bar}"))

    log.info("stop node %s", bar)
    bar.cmd("stop")

    log.info("remove %s cache directory", bar)
    shutil.rmtree(bar.sub("cache"))

    connect_nodes(foo, bar)

    log.info("make sure %s cache was recreated", bar)
    check.file_exists(bar.sub(f"cache/{foo}"))

    log.info("stop nodes")
    bar.cmd("stop")
    foo.cmd("stop")

    log.info("remove Address from all nodes")
    for node in foo, bar:
        node.cmd("del", "Address", code=None)
        for peer in foo, bar:
            node.cmd("del", f"{peer}.Address", code=None)
    bar.cmd("add", "ConnectTo", foo.name)

    log.info("make sure connection works using just the cached address")
    foo.cmd("start")
    connect_nodes(foo, bar)


with Test("run address cache tests") as context:
    run_tests(context)
