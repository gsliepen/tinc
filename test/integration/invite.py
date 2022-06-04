#!/usr/bin/env python3
# pylint: disable=import-outside-toplevel

"""Test tinc peer invitations."""

import time
import subprocess as subp

from testlib import check, util
from testlib.proc import Tinc
from testlib.log import log
from testlib.test import Test


def run_port0_test(ctx: Test) -> None:
    """Checks that tinc invite fails if called with Port 0 and tincd stopped."""
    foo = ctx.node(init=True)
    _, err = foo.cmd("invite", "bar", code=1)
    check.is_in("Please start tincd", err)


def init(ctx: Test) -> Tinc:
    """Initialize a node."""
    foo = ctx.node()
    stdin = f"""
        init {foo}
        set Port 12345
        set Address localhost
        set DeviceType dummy
        set Mode switch
        set Broadcast no
    """
    foo.cmd(stdin=stdin)
    return foo


def run_expiration_test(ctx: Test) -> None:
    """Make sure that invites can't be used after expiration date."""

    foo, bar = init(ctx), ctx.node()
    foo.cmd("set", "InvitationExpire", "1")
    foo.start()

    url, _ = foo.cmd("invite", bar.name)
    url = url.strip()
    time.sleep(2)

    try:
        bar.cmd("join", url, code=1, timeout=1)
    except subp.TimeoutExpired:
        pass

    foo.cmd("stop")
    foo_log = util.read_text(foo.sub("log"))
    check.is_in("tried to use expired invitation", foo_log)


def run_invite_test(ctx: Test, start_before_invite: bool) -> None:
    """Run tests. If start_before_invite is True,
    tincd is started *before* creating invitation, and vice versa.
    """
    foo = init(ctx)
    bar = ctx.node()

    if start_before_invite:
        foo.cmd("set", "Port", "0")
        port = foo.start()

    log.info("create invitation")
    foo_invite, _ = foo.cmd("invite", bar.name)
    assert foo_invite
    foo_invite = foo_invite.strip()

    if not start_before_invite:
        foo.cmd("set", "Port", "0")
        port = foo.start()
        foo_invite = foo_invite.replace(":12345/", f":{port}/")

    log.info("join second node with %s", foo_invite)
    bar.cmd("join", foo_invite)
    bar.cmd("set", "Port", "0")

    if not start_before_invite:
        log.info("%s thinks %s is using port 0, updating", bar, foo)
        bar.cmd("set", f"{foo}.Port", str(port))

    log.info("compare configs")
    check.files_eq(foo.sub("hosts", foo.name), bar.sub("hosts", foo.name))

    log.info("compare keys")

    prefix = "Ed25519PublicKey"
    foo_key = util.find_line(foo.sub("hosts", bar.name), prefix)
    bar_key = util.find_line(bar.sub("hosts", bar.name), prefix)
    check.equals(foo_key, bar_key)

    log.info("checking Mode")
    bar_mode, _ = bar.cmd("get", "Mode")
    check.equals("switch", bar_mode.strip())

    log.info("checking Broadcast")
    bar_bcast, _ = bar.cmd("get", "Broadcast")
    check.equals("no", bar_bcast.strip())

    log.info("checking ConnectTo")
    bar_conn, _ = bar.cmd("get", "ConnectTo")
    check.equals(foo.name, bar_conn.strip())

    log.info("configuring %s", bar.name)
    bar.cmd("set", "DeviceType", "dummy")

    log.info("adding scripts")
    foo.add_script(bar.script_up)
    bar.add_script(foo.script_up)

    log.info("starting %s", bar.name)
    bar.cmd("start")

    log.info("waiting for nodes to come up")
    foo[bar.script_up].wait()
    bar[foo.script_up].wait()

    log.info("checking required nodes")
    check.nodes(foo, 2)
    check.nodes(bar, 2)


with Test("fail with Port 0 and tincd not running") as context:
    run_port0_test(context)

with Test("offline mode") as context:
    run_invite_test(context, start_before_invite=False)

with Test("online mode") as context:
    run_invite_test(context, start_before_invite=True)

with Test("invite expiration") as context:
    run_expiration_test(context)
