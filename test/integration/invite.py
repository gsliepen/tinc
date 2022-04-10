#!/usr/bin/env python3
# pylint: disable=import-outside-toplevel

"""Test tinc peer invitations."""

from testlib import check, util
from testlib.log import log
from testlib.test import Test


def run_invite_test(ctx: Test, start_before_invite: bool) -> None:
    """Run tests. If start_before_invite is True,
    tincd is started *before* creating invitation, and vice versa.
    """
    foo, bar = ctx.node(), ctx.node()

    stdin = f"""
        init {foo}
        set Port 0
        set Address localhost
        set DeviceType dummy
        set Mode switch
        set Broadcast no
    """
    foo.cmd(stdin=stdin)

    if start_before_invite:
        port = foo.start()

    log.info("create invitation")
    foo_invite, _ = foo.cmd("invite", bar.name)
    assert foo_invite
    foo_invite = foo_invite.strip()

    if not start_before_invite:
        port = foo.start()
        foo_invite = foo_invite.replace(":0/", f":{port}/")

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


with Test("offline mode") as context:
    run_invite_test(context, start_before_invite=False)

with Test("online mode") as context:
    run_invite_test(context, start_before_invite=True)
